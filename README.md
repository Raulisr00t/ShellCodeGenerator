# 💀 ShellcodeGenerator

> A powerful Linux-based utility to generate customized Windows reverse shellcode directly from inline x86 NASM assembly.

![ShellcodeGenerator Banner](https://img.shields.io/badge/NASM-Shellcode-orange?style=flat-square&logo=nasm)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/Language-Nim-yellow?style=flat-square&logo=nim)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 🚀 About

**ShellcodeGenerator** is a custom tool written in **Nim** that dynamically patches IP and port values into hand-crafted x86 assembly shellcode (NASM syntax) for **Windows reverse shells**.

It compiles and links the shellcode into a PE binary (`.exe`) and extracts printable shellcode bytes suitable for exploitation tasks, malware research, or CTFs.

---

## 📦 Features

✅ Patch any IP address and port into shellcode  
✅ Fully x86 NASM compatible  
✅ Generates raw shellcode from compiled `.exe`  
✅ Written in Nim for speed and flexibility  
✅ Linux-only for ethical red teaming and malware research  
✅ Highlights correct little-endian formatting for network values

---

## ✅ Advantages

- 🔓 **Non-Signature Shellcode**  
  The generated shellcode does **not rely on common payload templates**, making it **unique on every run**. This effectively defeats most static signature-based detection techniques.

- 🛡️ **Bypasses Antivirus (AV) Engines**  
  Due to its polymorphic nature and absence of known patterns, this shellcode can evade many modern **AV and EDR solutions**, making it ideal for red team operations and stealthy post-exploitation.

- 🧬 **No External Dependencies**  
  Fully self-contained: no Metasploit, no PowerShell, no external loaders—pure, raw shellcode.

- 🎯 **Precision Targeting**  
  Configurable target IP and port are directly embedded in little-endian format at compile time, reducing runtime footprint.

---

## 🧪 Requirements

- Linux OS (any distro)
- [`nasm`](https://www.nasm.us/) — Netwide Assembler
- [`ld`](https://linux.die.net/man/1/ld) — GNU linker
- Nim Compiler (`nim`)

---

## ⚙️ Installation

Install Nim:
```bash
sudo apt install nim
```

Install Nasm and LD 
```bash
sudo apt install nasm binutils
```

Clone The Repository
```bash
git clone https://github.com/Raulisr00t/ShellcodeGenerator.git
cd ShellcodeGenerator
```

## 🛠️ Usage
```bash
nim c -d:release generator.nim
./generator <IP> <PORT>
```

Example
```bash
./generator 192.168.0.100 4444
```

Output:
```bash
[*] Replacing IP with: 0x6400a8c0
[*] Replacing PORT with: 0x5c11
[+] Written modified assembly to root.nasm
[+] Assemble root.nasm
[+] Linking
[+] Done !
Printing Shellcode
"\x31\xc9\x89\x00\x00\x00..."
```

## 📂 File Structure
```bash
.
├── generator.nim      # Main tool logic
├── root.nasm          # Modified NASM shellcode (auto-generated)
├── reverse.exe        # Compiled shellcode payload (auto-generated)
└── README.md          # Documentation
```

## 🧠 How It Works
Assembly Template: Inline NASM with placeholders for IP and port
Patch Engine: Replaces relevant lines using regex with correct little-endian values
Shellcode Extraction: Uses objdump and shell pipelines to extract clean, printable shellcode

## 🔐 Disclaimer
This tool is intended for educational purposes, malware research, and red teaming only.
You are solely responsible for how you use this code.
Do not deploy against systems you do not own or have explicit permission to test.

## ✨ Author
Developed by Raul
Drop a ⭐ if this helped you — and hack responsibly!
