# pktforge

`pktforge` is a Packet Tracer file decoder and study helper for `.pkt` and `.pka` files.

It started from the original [`ptexplorer.py`](https://github.com/axcheron) by **axcheron**, and this version has been extended and refocused for Packet Tracer 7.3.0 workflows, with stronger live-dump extraction and structured device-oriented output.

## What it does

- Tries the legacy XOR + zlib decode path first
- Falls back to a live Packet Tracer memory extraction when needed
- Produces a structured inventory by device
- Groups per-device configs into readable sections
- Writes a JSON sidecar for easier study and scripting

## Output files

- `decoded.txt`
- `decoded.json`

## Usage

```powershell
python312 .\pktforge.py -d .\input.pkt .\decoded.txt
```

To include the raw memory appendix as well:

```powershell
python312 .\pktforge.py -d .\input.pkt .\decoded.txt --include-raw
```

## Credits

- Original project: [`ptexplorer.py`](https://github.com/axcheron) by **axcheron**
- Current fork and adaptation: **Schryzon**

## Notes

- This project is useful for analysis and study of Packet Tracer artifacts.
- The fallback extractor depends on a running Packet Tracer process when the legacy on-disk wrapper cannot be decoded directly.

## GitHub tracking

If you want to publish this repo to GitHub:

1. Create a new empty repository on GitHub.
2. Add the remote in this folder.
3. Commit the files and push.

Example:

```powershell
git remote add origin https://github.com/<you>/pktforge.git
git add .
git commit -m "Initial public release"
git push -u origin master
```
