# Capstone Disassembly Framework

[Capstone](https://github.com/capstone-engine/capstone) is a lightweight multi-platform, multi-architecture disassembly framework. It is widely used for reverse engineering, binary analysis, and security research. Capstone provides a rich API to analyze machine code instructions in a fast and convenient way.

## Features

- Supports multiple architectures, including x86, x86_64, ARM, ARM64, MIPS, PowerPC, and more.
- Provides detailed instruction information (mnemonics, operands, registers used, etc.).
- High performance and lightweight design.
- Cross-platform support: works on Windows, macOS, Linux, and other systems.
- Multi-language bindings: C, Python, Java, C#, Go, Ruby, and others.

## Installation

You can clone the Capstone repository and build it manually:

```bash
git clone https://github.com/capstone-engine/capstone.git
cd capstone
make
sudo make install
