# AGENTS.md: Developer and AI Agent Technical Reference for pktforge / pktcore

## 1. System Overview

pktcore is an offline, high-throughput cryptographic decompiler, compiler, and automated challenge-authoring engine for Cisco Packet Tracer 7.x and legacy save formats (.pkt and .pka).

Prior approaches relied on inspecting running GUI instances of packettracer7.exe via Windows Win32 debugging APIs (VirtualQueryEx and ReadProcessMemory). pktcore completely bypasses the Packet Tracer application runtime. It reverses the proprietary cryptographic pipeline directly in memory, yielding the intact XML DOM tree in approximately 10 milliseconds, and enables losslessly modifying device configurations, canvas storyboards, rulesets, and web services on the fly.

---

## 2. Cryptographic Architecture and Pipeline

Packet Tracer 7.x utilizes a symmetric four-stage pipeline combining position-dependent XOR transformations, standard zlib compression with a Qt header, and the Twofish block cipher in EAX authenticated encryption mode.

### 2.1 Cryptographic Constants
- Block Cipher: Twofish-128
- Cipher Mode: EAX (Authenticated Encryption with Associated Data)
- Static Key: 16 bytes of 0x89 (`b"\x89" * 16`)
- Static Nonce / IV: 16 bytes of 0x10 (`b"\x10" * 16`)
- Associated Data (AAD): Empty (`b""`)
- Tag Length: 16 bytes (placed at the end of the Stage 1 buffer)

### 2.2 Decompilation Flow (.pkt -> XML)
1. Stage 1 Deobfuscation:
   Given input raw bytes `in_data` of length `L`:
   ```text
   stage1[i] = in_data[L - 1 - i] ^ ((L - i * L) & 0xFF)
   ```
2. Twofish-EAX Authentication and Decryption:
   - Split `stage1` into `ciphertext = stage1[:L - 16]` and `tag = stage1[L - 16:]`.
   - Calculate nonce MAC: `n_tag = OMAC1(0x00 || IV)`.
   - Calculate header MAC: `h_tag = OMAC1(0x01 || b"")`.
   - Decrypt `ciphertext` via CTR mode with initial counter `n_tag`.
   - Calculate ciphertext MAC: `c_tag = OMAC1(0x02 || ciphertext)`.
   - Verify tag: `expected_tag = n_tag ^ h_tag ^ c_tag`. If `expected_tag != tag`, raise authentication failure.
3. Stage 2 Deobfuscation:
   Given decrypted buffer `dec` of length `M = L - 16`:
   ```text
   stage2[i] = dec[i] ^ ((M - i) & 0xFF)
   ```
4. Qt zlib Decompression:
   - First 4 bytes are Big-Endian unsigned 32-bit integer representing the uncompressed XML byte length.
   - The remaining bytes are passed to standard zlib `decompress()`.
   - The uncompressed stream is truncated to the specified length to yield the valid UTF-8 XML document.

### 2.3 Compilation Flow (XML -> .pkt)
The process is executed in reverse:
1. `compressed = struct.pack(">I", len(xml_bytes)) + zlib.compress(xml_bytes)`
2. `stage2_obf[i] = compressed[i] ^ ((len(compressed) - i) & 0xFF)`
3. Twofish-EAX encryption of `stage2_obf` produces `ciphertext` and 16-byte `tag`.
4. Combine `stage1_raw = ciphertext + tag`.
5. Apply reverse mirror XOR:
   ```text
   output[L - 1 - i] = stage1_raw[i] ^ ((L - i * L) & 0xFF)
   ```

### 2.4 Acceleration Engine
- Native C Accelerator (`pktcore/c_src/pkt_fast_crypto.c` + `twofish.c`):
  Compiled via local GCC with `-O3 -shared` to `pkt_fast_crypto.dll`. Decompilation of a 200 KB `.pkt` file (which expands to over 3 MB of XML) executes in 10-15 milliseconds.
- Pure Python Fallback (`pktcore/crypto/`):
  Implemented in `twofish_py.py`, `cmac_py.py`, `ctr_py.py`, `eax_py.py`. Requires zero compilation or external libraries.

---

## 3. Packet Tracer XML DOM Specification (`PACKETTRACER5`)

The root element of the uncompressed document is `<PACKETTRACER5>` with version string `<VERSION>7.3.0.0838</VERSION>`.

### 3.1 Canvas Notes and Challenge Narration (`<NOTE>`)
Located under `<NETWORK><NOTES>` or inside logical clusters.
```xml
<NOTE uuid="{69b3b427-a6f9-43cf-b612-73cd79fcadc0}">
  <X>2321.0</X>
  <Y>2189.0</Y>
  <Z>40007.0</Z>
  <TEXT>RULE SET:
1. Semua access point harus punya DHCP pool
2. Tiap anak laser hanya saling terkoneksi di bagian dalamnya...
  </TEXT>
  <NOTECLUSTERID>1-1</NOTECLUSTERID>
  <MEM_ADDR>388870368</MEM_ADDR>
</NOTE>
```
- Coordinates (`X`, `Y`, `Z`): Canvas positioning floats or integers.
- `uuid`: Standard bracketed GUID string.
- `TEXT`: Plain text or markdown-style string displayed directly on the Packet Tracer workspace.

### 3.2 Devices and Configurations (`<DEVICE>`)
Located under `<NETWORK><DEVICES><DEVICE>`.
Key sub-elements inside `<ENGINE>`:
- `<NAME>`: Hostname / label (e.g. `Router1`, `CONFLICT`, `Switch0`).
- `<TYPE>`: Device class (e.g. `Router`, `Switch`, `PC`, `Server`, `AccessPoint`).
- `<RUNNINGCONFIG>`: Contains child `<LINE>` elements representing raw Cisco IOS command lines.
  ```xml
  <RUNNINGCONFIG>
    <LINE>hostname Router</LINE>
    <LINE>interface FastEthernet0/0</LINE>
    <LINE> ip address 69.67.0.145 255.255.255.240</LINE>
    <LINE> duplex auto</LINE>
    <LINE> speed auto</LINE>
    <LINE>!</LINE>
  </RUNNINGCONFIG>
  ```
- `<PORT>`: Hardware interface parameters including `<IP>`, `<SUBNET>`, `<MACADDRESS>`, `<BANDWIDTH>`, `<FULLDUPLEX>`, and `<POWER>`.

### 3.3 Web Server Files (`<FILE_MANAGER>`)
Servers hosting HTTP / DNS / TFTP services store files under `<FILE_MANAGER><FILE>`:
- `<FILE_NAME>`: File path (e.g. `index.html`, `helloworld.html`).
- `<FILE_CONTENT class="CHttpPage">`: Raw HTML/CSS text served by the simulated HTTP daemon.

### 3.4 Activity Wizard Rulesets (`<ANSWER_TREE_CHECK_BOX>`)
Packet Tracer Activity (.pka) files and activity-enabled .pkt files store the grading rule evaluation tree as a comma-separated path string:
`Device#Network#1,Interface#Router#0,IPAddress#FastEthernet0/0#Router#1...`
The integer suffix specifies the grading weight or boolean evaluation flag.

---

## 4. Python API Reference (`pktcore`)

### 4.1 `Pkt_Pipeline`
Location: `pktcore.crypto.pipeline.Pkt_Pipeline`

```python
from pktcore.crypto.pipeline import Pkt_Pipeline

pipeline = Pkt_Pipeline()

# Decompile .pkt bytes to raw XML bytes
xml_bytes = pipeline.decompile(raw_pkt_bytes)

# Compile raw XML bytes back to valid .pkt bytes
new_pkt_bytes = pipeline.compile(xml_bytes)
```

### 4.2 `Challenge_Manager`
Location: `pktcore.model.challenge.Challenge_Manager`

```python
from pktcore.model.challenge import Challenge_Manager

mgr = Challenge_Manager(xml_bytes)

# List all notes
notes = mgr.list_notes()

# Search for specific rules
rule_notes = mgr.get_rule_notes()

# Update note text
mgr.update_note_text(note_uuid="{69b3b427-a6f9-43cf-b612-73cd79fcadc0}", new_text="Updated Rule...")

# Add note
new_note = mgr.add_note(text="New Hint", x=1500, y=1200)

# Delete note
mgr.remove_note(note_uuid="{...}")

# Export updated XML
updated_xml = mgr.to_xml_bytes()
```

### 4.3 `Topology_Model`
Location: `pktcore.model.topology.Topology_Model`

```python
from pktcore.model.topology import Topology_Model

topo = Topology_Model(xml_bytes)

# Inspect all devices
for dev in topo.list_devices():
    print(dev.name, dev.device_type, len(dev.running_config))

# Export all Cisco IOS configs to a directory
topo.export_configs_to_dir("./exported_configs")

# Update running config
topo.set_running_config("Router1", ["hostname Router1", "interface FastEthernet0/0", "end"])
```

---

## 5. CLI Usage Guide

### Decompilation
```powershell
# Decompile .pkt to XML
python312 pktforge.py decompile input.pkt -o output.xml

# Decompile and simultaneously export all device Cisco IOS configs
python312 pktforge.py decompile input.pkt -o output.xml --dump-configs ./ios_configs
```

### Compilation
```powershell
# Compile XML to .pkt
python312 pktforge.py compile output.xml -o final.pkt
```

### Challenge Narration and Ruleset Operations
```powershell
# List all canvas notes, story narration, and web files
python312 pktforge.py challenge list input.pkt

# Edit rule note in-place (auto-detects rule note UUID if omitted)
python312 pktforge.py challenge edit input.pkt -o updated.pkt --text "RULE SET: New criteria"

# Edit rule note from an external file
python312 pktforge.py challenge edit input.pkt -o updated.pkt --file new_rules.txt

# Add a new canvas note
python312 pktforge.py challenge add input.pkt -o updated.pkt --text "Exam Room Notice" --x 2400 --y 1800
```

### Device Inventory
```powershell
# Display all 100+ devices, models, and assigned interface IP addresses
python312 pktforge.py devices input.pkt
```

---

## 6. Common Agent Workflows

### Recipe: Automated Challenge Randomization
When generating randomized student challenges from a base `.pkt` template:
1. Load base file: `xml_data = pipeline.decompile(template_pkt)`.
2. Instantiate `Challenge_Manager(xml_data)` and `Topology_Model(xml_data)`.
3. Generate student-specific parameters (e.g. Subnet base `69.67.{student_id}.0/28`, unique VLAN ID).
4. Update canvas rule notes with student instructions via `mgr.update_note_text()`.
5. Update router interface IPs and running config lines via `topo.set_running_config()`.
6. Compile final file: `student_pkt = pipeline.compile(mgr.to_xml_bytes())`.
7. Execution time is under 50 milliseconds per variant.
