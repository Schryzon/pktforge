# pktforge

🇺🇸 [English](README.md) | 🇮🇩 [Bahasa Indonesia](README_ID.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Scoop](https://img.shields.io/badge/Scoop-python312-4285F4.svg)](https://scoop.sh/)
[![Packet Tracer](https://img.shields.io/badge/Cisco%20Packet%20Tracer-7.0%20--%207.3.0%2B-008080.svg?logo=cisco&logoColor=white)](https://www.netacad.com/)
[![Speed](https://img.shields.io/badge/Speed-10ms%20Decompile-success.svg)](#performance-benchmarks)
[![Sponsor Schryzon](https://img.shields.io/badge/Sponsor-Schryzon-ea4aaa.svg?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Schryzon)

`pktforge` is a high-speed, offline Cisco Packet Tracer 7.x (.pkt and .pka) decompiler, compiler, and challenge automation suite.

It completely eliminates the need to run Cisco Packet Tracer for inspection, challenge authoring, or configuration extraction. By directly implementing the native cryptographic pipeline (Twofish-128 in EAX mode with dual-stage position-dependent obfuscation), `pktforge` decrypts and recompiles complex network topologies losslessly in sub-frame time (10 to 50 milliseconds).

## Core Capabilities

- Pure Offline Operation: Zero dependency on `packettracer7.exe`, GUI, or live process memory dumping.
- Sub-Frame Performance: Built-in C-accelerator compiles on first run via GCC with `-O3` to deliver 10-15 ms decryptions for 3+ MB XML topologies.
- Pure Python Fallback: Runs out-of-the-box on any Python 3.8+ system without native toolchains if required.
- Challenge Authoring Engine: Read, edit, or add canvas notes, story narration, and rulesets on the fly without manual GUI positioning.
- Device Configuration Automation: Extract, inspect, and export Cisco IOS running-configurations across hundreds of devices simultaneously.
- AI & Agentic Native: Feeds clean, deterministic XML and device JSON into AI agents (or LLMs) to construct, revise, and verify challenge narratives and rulesets automatically.
- 7 Hours of Freedom in 2 Minutes: Replaces the exhausting chore of clicking through hundreds of device GUI dialogs with a token-efficient, automated workflow.
- Lossless Roundtrips: Fully reversible compilation back to native `.pkt` files that open directly in Cisco Packet Tracer 7.3.0.

## System Requirements and Dependencies

| Component | Recommended Specification | Requirement Level | Purpose | Setup / Installation Command |
| :--- | :--- | :--- | :--- | :--- |
| Python Runtime | Python 3.12 (via Scoop `python312`) | Required | Executes CLI, XML DOM manipulation, and pure-Python crypto engine | `scoop bucket add versions; scoop install python312` |
| C Compiler | GCC 13+ (MSYS2 UCRT64 or MinGW) | Optional (Recommended) | Auto-compiles native C Twofish-EAX acceleration DLL for sub-frame (10 ms) performance | `scoop install gcc` or MSYS2 installer |
| Shell Environment | PowerShell 7+ (pwsh) | Recommended | Standard terminal environment for command pipelining and automation | `scoop install pwsh` |
| Python Packages | Standard Library (`ctypes`, `zlib`, `struct`, `xml`) | Built-in | Zero external third-party pip dependencies required | Pre-installed with Python |
| Supported Formats | Cisco Packet Tracer 7.0 - 7.3.0+ (`.pkt`, `.pka`) | Target Input/Output | Decompiles, modifies, and compiles valid Packet Tracer topology saves | N/A |

## Installation & Setup

It is strongly recommended to use Python 3.12 managed via the Scoop package manager `versions` bucket for predictable interpreter paths and system isolation:

```powershell
# 1. Install Python 3.12 via Scoop (Recommended)
scoop bucket add versions
scoop install python312

# 2. Clone the repository
git clone https://github.com/Schryzon/pktforge.git
cd pktforge

# 3. Verify installation and CLI access
python312 pktforge.py --help
```

If GCC is present on your system PATH (e.g. from MSYS2 or Scoop), `pktforge` will automatically detect it and compile the native C accelerator (`pkt_fast_crypto.dll`) on the very first run. If no C compiler is available, `pktforge` automatically and seamlessly falls back to its built-in pure Python cryptographic engine.

## Usage Guide

### 1. Decompile .pkt to XML
```powershell
python312 pktforge.py decompile input.pkt -o topology.xml
```

To simultaneously dump all device Cisco IOS configs into a folder:
```powershell
python312 pktforge.py decompile input.pkt -o topology.xml --dump-configs ./configs
```

### 2. Compile XML to .pkt
```powershell
python312 pktforge.py compile topology.xml -o output.pkt
```

### 3. Inspect Canvas Notes and Challenge Rules
```powershell
python312 pktforge.py challenge list input.pkt
```

### 4. Edit Challenge Rules On The Fly
Modify the primary rule set note directly and output a new `.pkt`:
```powershell
python312 pktforge.py challenge edit input.pkt -o challenge_mod.pkt --text "RULE SET: 1. DHCP required. 2. Subnet 69.67.10.0/28"
```

Or load rules from a text file:
```powershell
python312 pktforge.py challenge edit input.pkt -o challenge_mod.pkt --file new_rules.txt
```

### 5. Add a New Canvas Note
```powershell
python312 pktforge.py challenge add input.pkt -o challenge_mod.pkt --text "Hint: Check VLAN 10 tagging" --x 2200 --y 1800
```

### 6. Inspect Devices and IP Assignments
```powershell
python312 pktforge.py devices input.pkt
```

### Backward Compatibility
Legacy CLI flags `-d` and `-e` are preserved for backward compatibility:
```powershell
python312 pktforge.py -d input.pkt decoded.xml
python312 pktforge.py -e decoded.xml output.pkt
```

## Sample Output Examples (Masked)

### 1. Decompilation Output
Command:
```powershell
python312 pktforge.py decompile lab_topology.pkt -o topology.xml
```

Console output:
```text
[*] Reading 'lab_topology.pkt' (207,550 bytes)...
[*] Decrypting with C-Accelerator (Sub-frame)...
[+] Decrypted in 10.74 ms! XML size: 3,009,125 bytes
[+] Written XML to 'topology.xml'
```

Extracted XML DOM snippet (`topology.xml`):
```xml
<PACKETTRACER5>
  <VERSION>7.3.0.0838</VERSION>
  <NETWORK>
    <DEVICES>
      <DEVICE>
        <ENGINE>
          <TYPE model="Router-PT-Empty">Router</TYPE>
          <NAME>CORE-ROUTER-01</NAME>
          <RUNNINGCONFIG>
            <LINE>hostname CORE-ROUTER-01</LINE>
            <LINE>interface FastEthernet0/0</LINE>
            <LINE> ip address 10.10.x.1 255.255.255.240</LINE>
            <LINE> duplex auto</LINE>
            <LINE> speed auto</LINE>
            <LINE>!</LINE>
          </RUNNINGCONFIG>
        </ENGINE>
      </DEVICE>
    </DEVICES>
  </NETWORK>
</PACKETTRACER5>
```

### 2. Challenge & Storyboard Inspection Output
Command:
```powershell
python312 pktforge.py challenge list lab_topology.pkt
```

Console output:
```text
=== Canvas Notes & Storyboard (123 items) ===
[01] UUID: {69b3b427-xxxx-xxxx-xxxx-73cd79fcadc0} | Pos: (2321.0, 2189.0)
     Text: RULE SET: 1. Semua access point harus punya DHCP pool...

[02] UUID: {327ef44c-xxxx-xxxx-xxxx-4a22fce8ea41} | Pos: (3497.0, 2060.0)
     Text: 10.10.x.x/28

[03] UUID: {dfcb94ec-xxxx-xxxx-xxxx-00101fe9c256} | Pos: (2221.0, 1826.0)
     Text: CLIENT MODE
```

### 3. Device Inventory & Configuration Summary Output
Command:
```powershell
python312 pktforge.py devices lab_topology.pkt
```

Console output:
```text
=== Network Device Inventory (103 devices) ===
• [Router] CORE-ROUTER-01 (Router-PT-Empty) | IOS Config: 132 lines
    Interfaces: FastEthernet0/0: 10.10.x.1/255.255.255.240, FastEthernet1/0: 10.10.x.17/255.255.255.240
• [Router] EDGE-ROUTER-02 (Router-PT-Empty) | IOS Config: 112 lines
    Interfaces: FastEthernet0/0: 10.10.x.33/255.255.255.240, FastEthernet1/0: 10.10.x.49/255.255.255.240
• [Switch] SW-DISTRIBUTION-01 (2950-24) | IOS Config: 84 lines
... and 100 more devices
```

### 4. On-The-Fly Rule Mutation Output
Command:
```powershell
python312 pktforge.py challenge edit lab_topology.pkt -o updated_topology.pkt --text "RULE SET: 1. Configure OSPF area 0. 2. Subnetting 10.10.x.0/28"
```

Console output:
```text
[*] Auto-detected rule note UUID: {69b3b427-xxxx-xxxx-xxxx-73cd79fcadc0}
[+] Successfully edited challenge note and saved to 'updated_topology.pkt' in 49.20 ms!
```

## Performance Benchmarks

Benchmarked on AMD Ryzen 7 6800H with `conflict-modul-4.pkt` (207 KB `.pkt` expanding to 3.01 MB XML, 80,676 lines, 103 devices):

- Decompilation (C Accelerator): 10.32 ms
- XML Parsing and Note Search: 2.10 ms
- Rule Modification and Re-encryption: 49.20 ms
- Total Roundtrip Time: < 65 ms

## Project Structure

- `pktforge.py`: Main CLI entry point.
- `pktcore/crypto/`: Cryptographic pipeline, Twofish cipher, EAX mode, CMAC, and C bridge.
- `pktcore/c_src/`: High-performance C implementations of Twofish and obfuscation routines.
- `pktcore/model/`: Domain models for canvas notes, challenge manager, and network topology.
- `AGENTS.md`: Full architectural and developer reference for automated AI agents.

## Sponsors & Support

If `pktforge` saved your hours, streamlined your laboratory practicum, or accelerated your research, consider supporting ongoing development:

- Sponsor via GitHub: [github.com/sponsors/Schryzon](https://github.com/sponsors/Schryzon)
- Developer: [Schryzon](https://github.com/Schryzon)
- Buy me a coffee: [ko-fi.com/Schryzon](https://ko-fi.com/schryzon)
- Saweria: [saweria.co/Schryzon](https://saweria.co/schryzon)

---

## Dedication to Computer Networking Lab Assistants

To the computer networking lab assistants (asisten laboratorium jaringan komputer), wherever you are, whenever you serve, and from whichever generation or batch you hail:

This project is dedicated to you.

We know the untold stories of your late nights in the lab: the endless hours spent manually clicking through Packet Tracer's GUI to inspect device dialogs after literally pouring your soul into designing complex challenge topologies, drafting and redrafting practicum modules, wrestling with application crashes right before exam day, and grading stacks of student submission files one by one until your eyes blur.

In this new era, clicking through GUIs just to view interface details and write down narrative storyboards across 100+ devices is an unnecessary, exhausting drain. If spending a few tokens in a few minutes with an AI agent can give you 7 hours of freedom back, then pktforge was built for you.

You carry the torch of networking education. You bridge the gap between abstract OSI models and real-world packet flow. You debug broken subnet masks and stubborn routing protocols so that the next generation of network engineers can learn, build, and connect the world.

Let AI handle the tedious narrative construction and iterative revisions. You design the genius topologies; let the automated machinery do the rest. Keep inspiring, keep troubleshooting, and never lose your passion for the craft.

---

## Contributing

Contributions, issues, and feature requests are warmly welcomed. Whether you are a network engineer, security researcher, educator, or student, your input helps make `pktforge` better for everyone.

### Ways to Contribute
- Feature Additions: Implementing parsers for additional Packet Tracer subsystems (e.g. IoT devices, complex PDU inspections, or newer Packet Tracer version profiles).
- Performance Optimizations: Refining native cryptographic routines or pure-Python fallback execution.
- Documentation & Examples: Adding challenge templates, AI prompt patterns for narrative generation, or translation updates.
- Bug Reports: Submitting issue reports with minimal reproducible `.pkt` samples when encountering decoding anomalies.

### Contribution Workflow
1. Fork the project repository.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m "Add amazing feature"`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

---

## Disclaimers

- Trademark Notice: Cisco, Cisco Packet Tracer, Cisco IOS, and related marks are registered trademarks of Cisco Systems, Inc. `pktforge` is an independent, community-driven reverse-engineering and educational research tool. It is not affiliated with, endorsed by, or sponsored by Cisco Systems, Inc.
- Intended Use & Academic Ethics: This software is created solely for legitimate educational automation, curriculum design, offline challenge authoring, and architectural research. Users, educators, and students are strictly responsible for upholding their respective institutional academic integrity codes and curriculum terms. The maintainers do not condone or support using this software for academic dishonesty or unauthorized evaluation tampering.
- Warranty: This software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.
