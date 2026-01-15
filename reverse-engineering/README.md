# Reverse Engineering Study: Simple Game Check

## Overview
Educational project demonstrating a basic reverse engineering workflow: static and dynamic analysis of a Windows executable. The goal is to identify a hardcoded validation key within a packed binary.

## Project Structure
- **`binary/`**: Contains the target executable (`simple_game_check.exe`).
- **`analysis/`**: Detailed reports for [Static Analysis](./analysis/static_analysis.md) and [Dynamic Analysis](./analysis/dynamic_analysis.md).
- **`screenshots/`**: Visual evidence from analysis tools.

## Workflow
1. **Static Analysis**: Inspection with Detect It Easy (DIE) to identify the packer (PyInstaller) and analyze the file structure.
2. **Dynamic Analysis**: Runtime memory inspection using Cheat Engine to locate and verify the secret key in RAM.

## Tools Used
- **Detect It Easy**: Signature, packer, and metadata analysis.
- **Cheat Engine**: Runtime memory scanning and value identification.

## Disclaimer
This project is for educational purposes only. It demonstrates defensive analysis techniques and does not involve bypassing actual security software or terms of service of any third-party application.