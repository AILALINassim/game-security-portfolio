# 🛡️ Game Security Portfolio

This repository showcases practical security research and defensive Proof of Concepts (PoC) focused on **Reverse Engineering**, **Anti-Tamper mechanisms**, and **Network Protocol Analysis**. 

## 📂 Project Modules

### 🔐 [Anti-Tamper Lite](./anti-tamper/)
- **Goal**: Implementation of a lightweight client-side protection module to detect unauthorized modifications.
- **Features**: 
    - **Integrity**: Real-time SHA-256 file hashing to detect binary corruption or injection.
    - **Detection**: Forbidden process heuristics (Cheat Engine, Debuggers) and Win32 `IsDebuggerPresent` checks.
- **Design**: Fully configurable via YAML with structured JSONL logging for audit trails.
- **Tools**: Python (psutil, pyyaml).

### 🌐 [Network Analysis](./network-analysis/)
- **Target**: Minecraft local loopback traffic (TCP port 25565).
- **Goal**: Analyze and reconstruct application-layer game traffic.
- **Outcome**: Documented the visibility of metadata in raw streams and developed a Python utility to replay payloads from Wireshark hexdumps.
- **Tools**: Wireshark, Python (socket).

### 🔍 [Reverse Engineering](./reverse-engineering/)
- **Target**: A Windows executable packed with PyInstaller.
- **Goal**: Identify hardcoded validation keys in a binary where static strings are compressed.
- **Outcome**: Successfully transitioned from static inspection to dynamic memory scanning, identifying a **2-byte** secret key in RAM.
- **Tools**: Detect It Easy (DIE), Cheat Engine 7.5.

## 🛠️ Global Toolbox
- **Static Analysis**: Detect It Easy (DIE), PE metadata inspection.
- **Dynamic Inspection**: Cheat Engine 7.5 (Memory scanning & forensics).
- **Network**: Wireshark (Packet interception & stream reconstruction).
- **Automation**: Python 3.10+ for custom tooling and response logic.

---
*Disclaimer: These projects are strictly for educational and defensive purposes. They demonstrate visibility and detection logic in controlled, local environments.*