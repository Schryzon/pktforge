#!/usr/bin/python3

"""pktforge: Packet Tracer file extractor and study-oriented decoder."""

__author__ = "Schryzon"
__license__ = "MIT License"
__version__ = "0.3"

import argparse
import ctypes
import ctypes.wintypes as wt
import io
import json
import os
import re
import subprocess
import sys
import zlib
from pathlib import Path


LEGACY_ZLIB_WBITS = (15, -15, 31)
LIVE_MARKERS = (
    b"CUSTOM_VARS",
    b"interface FastEthernet",
    b"no service password-encryption",
    b"ip address",
    b"MANAGEMENT_INTERFACE",
    b"ENT_INTERFACE",
)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wt.LPVOID),
        ("AllocationBase", wt.LPVOID),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def _xor_schedule(data):
    size = len(data)
    out = bytearray()

    for byte in data:
        out.append((byte ^ size) & 0xFF)
        size -= 1

    return bytes(out)


def _try_legacy_decode(infile):
    with open(infile, "rb") as f:
        in_data = f.read()

    print("[*] Opening Packet Tracer file '%s'" % infile)
    print("[*] File size compressed = %d bytes" % len(in_data))

    out = _xor_schedule(in_data)
    o_size = int.from_bytes(out[:4], byteorder="big", signed=False)
    print("[*] Legacy header size = %d bytes" % o_size)

    for wbits in LEGACY_ZLIB_WBITS:
        try:
            return zlib.decompress(out[4:], wbits=wbits)
        except zlib.error:
            pass

    raise zlib.error("legacy Packet Tracer wrapper did not decompress")


def _list_packet_tracer_pids():
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return []

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", wt.LONG),
            ("dwFlags", wt.DWORD),
            ("szExeFile", wt.WCHAR * wt.MAX_PATH),
        ]

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    pids = []
    first = kernel32.Process32FirstW
    first.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    first.restype = wt.BOOL
    next_proc = kernel32.Process32NextW
    next_proc.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    next_proc.restype = wt.BOOL

    try:
        if not first(snapshot, ctypes.byref(entry)):
            return []

        while True:
            if entry.szExeFile.lower() == "packettracer7.exe":
                pids.append(int(entry.th32ProcessID))
            if not next_proc(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return pids


def _open_process(pid):
    kernel32 = ctypes.windll.kernel32
    access = 0x0410
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError("OpenProcess failed for pid %d" % pid)
    return handle


def _iter_memory_regions(handle):
    kernel32 = ctypes.windll.kernel32
    query = kernel32.VirtualQueryEx
    query.argtypes = [wt.HANDLE, wt.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    query.restype = ctypes.c_size_t

    address = 0
    while address < 0x7FFF_FFFF_FFFF:
        mbi = MEMORY_BASIC_INFORMATION()
        if not query(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break

        yield address, mbi
        address += max(mbi.RegionSize, 0x1000)


def _read_memory(handle, address, size):
    kernel32 = ctypes.windll.kernel32
    read = kernel32.ReadProcessMemory
    read.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    read.restype = wt.BOOL

    buf = (ctypes.c_char * size)()
    nread = ctypes.c_size_t()
    ok = read(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(nread))
    if not ok:
        return b""
    return bytes(buf[:nread.value])


def _region_is_readable(mbi):
    if mbi.State != 0x1000:
        return False

    if mbi.Protect & 0x100:
        return False

    return bool(mbi.Protect & 0x02 or mbi.Protect & 0x04 or mbi.Protect & 0x20 or mbi.Protect & 0x40)


def _score_region(data):
    score = 0
    hits = []

    weighted_markers = (
        (b"CUSTOM_VARS", 6),
        (b"interface FastEthernet0/0", 10),
        (b"interface FastEthernet1/0", 10),
        (b"interface FastEthernet2/0", 10),
        (b"interface FastEthernet3/0", 10),
        (b"interface FastEthernet4/0", 10),
        (b"interface FastEthernet5/0", 10),
        (b"interface FastEthernet6/0", 10),
        (b"interface FastEthernet7/0", 10),
        (b"interface FastEthernet8/0", 10),
        (b"interface FastEthernet9/0", 10),
        (b"no service password-encryption", 6),
        (b"ip address", 1),
        (b"MANAGEMENT_INTERFACE", 1),
        (b"ENT_INTERFACE", 1),
        (b"RECENT_FILES", -3),
        (b"ALGORITHM_SETTINGS", -3),
        (b"<!DOCTYPE Options>", -6),
        (b"<OPTIONS>", -4),
    )

    def as_utf16le_bytes(text):
        return text.decode("ascii").encode("utf-16le")

    for marker, weight in weighted_markers:
        count = data.count(marker)
        utf16_count = 0
        if marker.isascii():
            utf16_count = data.count(as_utf16le_bytes(marker))
        count += utf16_count
        if count:
            score += weight * count
            if utf16_count:
                hits.append("%s x%d (utf16)" % (marker.decode("ascii", "ignore"), count))
            else:
                hits.append("%s x%d" % (marker.decode("ascii", "ignore"), count))

    required_markers = (
        b"CUSTOM_VARS",
        b"interface FastEthernet0/0",
        b"interface FastEthernet1/0",
    )
    required_utf16 = tuple(as_utf16le_bytes(marker) for marker in required_markers)
    if not any(marker in data for marker in required_markers) and not any(marker in data for marker in required_utf16):
        return 0, hits

    return score, hits


def _extract_strings(data):
    seen = set()
    strings = []

    for pattern, decoder in (
        (rb"[ -~]{6,}", lambda b: b.decode("ascii", "ignore")),
        (rb"(?:[ -~]\x00){6,}", lambda b: b.decode("utf-16le", "ignore")),
    ):
        for match in re.finditer(pattern, data):
            text = decoder(match.group())
            text = text.strip()
            if not text or text in seen:
                continue
            seen.add(text)
            strings.append(text)

    return strings


def _extract_html_fragments(data):
    fragments = []
    seen = set()

    for pattern in (
        rb"<[A-Za-z][^>]{0,200}>",
        rb"</[A-Za-z][^>]{0,200}>",
        rb"<html[^>]{0,200}>",
        rb"<body[^>]{0,200}>",
        rb"<head[^>]{0,200}>",
        rb"<title[^>]{0,200}>",
        rb"<!DOCTYPE[^>]{0,200}>",
    ):
        for match in re.finditer(pattern, data, re.IGNORECASE):
            text = match.group().decode("utf-8", "ignore").strip()
            if text and text not in seen:
                seen.add(text)
                fragments.append(text)

    return fragments


def _extract_ssids(strings):
    ssids = []
    seen = set()
    patterns = (
        re.compile(r"\bssid\b[:= ]+([A-Za-z0-9_.\-]{1,32})", re.IGNORECASE),
        re.compile(r"\bssid\b\s+([A-Za-z0-9_.\-]{1,32})", re.IGNORECASE),
        re.compile(r"\bssid\s*[:=]\s*([A-Za-z0-9_.\-]{1,32})", re.IGNORECASE),
    )

    for text in strings:
        for pattern in patterns:
            for match in pattern.finditer(text):
                ssid = match.group(1).strip()
                if ssid and ssid not in seen:
                    seen.add(ssid)
                    ssids.append(ssid)

    return ssids


def _is_config_line(text):
    prefixes = (
        "interface ",
        "ip ",
        "no ",
        "switchport ",
        "spanning-tree ",
        "hostname ",
        "line ",
        "vtp ",
        "router ",
        "access-list ",
        "banner ",
        "description ",
        "duplex ",
        "speed ",
        "clock rate ",
        "encapsulation ",
        "default-router ",
        "network ",
        "login",
        "transport ",
        "service ",
        "arp ",
        "standby ",
    )
    return text.startswith(prefixes)


def _parse_device_blocks(strings):
    blocks = []
    current = None
    pending_title = None
    known_keys = {
        "DEVICE_TYPE",
        "CUSTOM_IMAGE_LOGICAL",
        "CUSTOM_IMAGE_PHYSICAL",
        "DEVICE",
        "PARENT_PATH",
        "WORKSPACE",
        "LOGICAL",
        "PHYSICAL",
        "X_COORD",
        "Y_COORD",
        "Z_COORD",
        "hostname",
    }

    def start_block(token):
        nonlocal current
        if current is not None:
            current["title"] = pending_title
            blocks.append(current)
        current = {
            "save_ref_id": token.split(":", 1)[1].strip(),
            "title": None,
            "tokens": [],
            "interfaces": [],
            "configs": [],
            "config_groups": {},
            "links": [],
            "meta": {},
        }

    for token in strings:
        if token.startswith("save-ref-id:"):
            start_block(token)
            continue

        if current is None:
            pending_title = token
            continue

        current["tokens"].append(token)

    if current is not None:
        current["title"] = pending_title
        blocks.append(current)

    for block in blocks:
        tokens = block["tokens"]
        meta = block["meta"]
        interfaces = []
        configs = []
        links = []

        for idx, token in enumerate(tokens):
            if token in ("X_COORD", "Y_COORD", "Z_COORD") and idx + 1 < len(tokens):
                meta[token] = tokens[idx + 1]
                continue

            if token in ("DEVICE_TYPE", "CUSTOM_IMAGE_LOGICAL", "CUSTOM_IMAGE_PHYSICAL", "DEVICE", "PARENT_PATH", "WORKSPACE"):
                if idx + 1 < len(tokens) and tokens[idx + 1] not in known_keys and not _is_config_line(tokens[idx + 1]):
                    meta[token] = tokens[idx + 1]
                continue

            if token.startswith("interface "):
                interfaces.append(token)
                continue

            if token.startswith("ip route ") or token.startswith("ip address ") or token.startswith("vtp ") or token.startswith("switchport ") or token.startswith("spanning-tree "):
                configs.append(token)
                continue

            if token.startswith("hostname "):
                meta["hostname"] = token.split(" ", 1)[1]
                configs.append(token)
                continue

            if token.startswith("description "):
                configs.append(token)
                continue

            if "->" in token or token.startswith("link "):
                links.append(token)

        block["interfaces"] = interfaces
        block["configs"] = configs
        block["links"] = links

        if block["title"] and block["title"] not in known_keys and not _is_config_line(block["title"]):
            meta.setdefault("title", block["title"])

        if "hostname" not in meta:
            for token in tokens:
                if token.startswith("hostname "):
                    meta["hostname"] = token.split(" ", 1)[1]
                    break

    return blocks


def _device_display_name(block):
    meta = block["meta"]
    name = meta.get("hostname") or meta.get("DEVICE") or meta.get("CUSTOM_IMAGE_LOGICAL") or meta.get("CUSTOM_IMAGE_PHYSICAL")
    if not name or name == "unknown":
        name = _infer_device_type(block)
        if not name or name == "unknown":
            name = "device_%s" % block["save_ref_id"][:8]
    return name


def _device_display_type(block):
    meta = block["meta"]
    return meta.get("DEVICE_TYPE") or meta.get("CUSTOM_IMAGE_LOGICAL") or meta.get("CUSTOM_IMAGE_PHYSICAL") or _infer_device_type(block)


def _infer_device_type(block):
    meta = block["meta"]
    configs = block["configs"]
    interfaces = block["interfaces"]

    candidates = (
        meta.get("DEVICE_TYPE"),
        meta.get("CUSTOM_IMAGE_LOGICAL"),
        meta.get("CUSTOM_IMAGE_PHYSICAL"),
        meta.get("title"),
    )
    for candidate in candidates:
        if candidate and candidate not in ("unknown", "MEM_ADDR") and not _is_config_line(candidate):
            return candidate

    lower_configs = [line.lower() for line in configs]
    interface_count = len(interfaces)

    if any("ssid" in line for line in lower_configs) or any("dot11" in line for line in lower_configs):
        return "Wireless Device"
    if any("vtp " in line or "switchport " in line for line in lower_configs):
        return "Switch"
    if any("ip route " in line for line in lower_configs) and interface_count >= 2:
        return "Router"
    if any("ip dhcp " in line for line in lower_configs):
        return "Server"
    if any("http" in line or "<html" in line for line in lower_configs):
        return "Server/Web"
    if any("access point" in line for line in lower_configs):
        return "Access Point"
    if interface_count and interface_count <= 2:
        return "End Device"
    if interface_count > 2:
        return "Network Device"

    return "unknown"


def _group_configs(configs):
    groups = {
        "interfaces": [],
        "routing": [],
        "dhcp": [],
        "wireless": [],
        "security": [],
        "system": [],
        "web": [],
        "other": [],
    }

    for line in configs:
        lower = line.lower()
        if lower.startswith("interface "):
            groups["interfaces"].append(line)
        elif lower.startswith(("ip route ", "router ", "network ", "default-router ", "ip flow-export ")):
            groups["routing"].append(line)
        elif lower.startswith(("ip dhcp ", "dhcp ", "lease ", "option ", "dns-server ")):
            groups["dhcp"].append(line)
        elif lower.startswith(("ssid", "wlan", "dot11", "authentication ", "encryption ", "radio ", "channel ", "broadcast ", "ap name", "mac-filter")):
            groups["wireless"].append(line)
        elif lower.startswith(("vtp ", "switchport ", "spanning-tree ", "access-list ", "enable secret", "service ", "username ", "line ", "login", "banner ", "no cdp run", "no service password-encryption")):
            groups["security"].append(line)
        elif lower.startswith(("hostname ", "no ", "ip address ", "speed ", "duplex ", "clock rate ", "description ", "encapsulation ", "transport ", "arp ", "standby ")):
            groups["system"].append(line)
        elif "http" in lower or "<html" in lower or "</html" in lower or "web" in lower:
            groups["web"].append(line)
        else:
            groups["other"].append(line)

    return groups


def _configs_to_json(configs):
    return {name: values[:] for name, values in _group_configs(configs).items()}


def _format_device_blocks(strings):
    blocks = _parse_device_blocks(strings)
    ssids = _extract_ssids(strings)
    html = _extract_html_fragments("\n".join(strings).encode("utf-8", "ignore"))
    out = []
    out.append("[packettracer_devices]")
    out.append("device_count=%d" % len(blocks))
    if ssids:
        out.append("ssid_count=%d" % len(ssids))
    if html:
        out.append("html_fragment_count=%d" % len(html))
    out.append("")

    if ssids:
        out.append("[wireless]")
        for ssid in ssids:
            out.append("ssid=%s" % ssid)
        out.append("")

    if html:
        out.append("[html_fragments]")
        out.extend(html)
        out.append("")

    for index, block in enumerate(blocks, 1):
        meta = block["meta"]
        name = _device_display_name(block)
        grouped = _group_configs(block["configs"])
        config_count = sum(len(values) for values in grouped.values())
        out.append("[%s]" % name)
        out.append("save_ref_id=%s" % block["save_ref_id"])
        out.append("name=%s" % name)
        out.append("type=%s" % _device_display_type(block))
        out.append(
            "summary=interfaces:%d configs:%d links:%d"
            % (len(block["interfaces"]), config_count, len(block["links"]))
        )
        if "X_COORD" in meta or "Y_COORD" in meta or "Z_COORD" in meta:
            out.append(
                "position=%s,%s,%s"
                % (meta.get("X_COORD", ""), meta.get("Y_COORD", ""), meta.get("Z_COORD", ""))
            )
        if "PARENT_PATH" in meta:
            out.append("parent_path=%s" % meta["PARENT_PATH"])
        if "WORKSPACE" in meta:
            out.append("workspace=%s" % meta["WORKSPACE"])

        if block["interfaces"]:
            out.append("interfaces=%s" % ", ".join(block["interfaces"]))
        if block["links"]:
            out.append("links=%s" % ", ".join(block["links"]))

        if block["configs"]:
            out.append("")
            out.append("[config]")
            out.extend(block["configs"])
        for section_name in ("interfaces", "routing", "dhcp", "wireless", "security", "system", "web", "other"):
            section = grouped[section_name]
            if section:
                out.append("")
                out.append("[%s]" % section_name)
                out.extend(section)
        extra = [line for line in strings if "http" in line.lower() or "<html" in line.lower() or "</html" in line.lower()]
        if extra:
            out.append("")
            out.append("[related_artifacts]")
            for line in extra[:80]:
                out.append(line)

        out.append("")

    return "\n".join(out).encode("utf-8")


def _build_json_report(strings, best):
    blocks = _parse_device_blocks(strings)
    report = {
        "packettracer_live_dump": {
            "pid": best["pid"],
            "region": "0x%x" % best["base"],
            "bytes": best["size"],
            "score": best["score"],
            "markers": best["hits"],
        },
        "wireless": _extract_ssids(strings),
        "html_fragments": _extract_html_fragments("\n".join(strings).encode("utf-8", "ignore")),
        "devices": [],
    }

    for block in blocks:
        meta = block["meta"]
        configs = _group_configs(block["configs"])
        report["devices"].append(
            {
                "save_ref_id": block["save_ref_id"],
                "name": _device_display_name(block),
                "type": _device_display_type(block),
                "title": block.get("title"),
                "summary": {
                    "interfaces": len(block["interfaces"]),
                    "configs": sum(len(values) for values in configs.values()),
                    "links": len(block["links"]),
                },
                "position": {
                    "x": meta.get("X_COORD"),
                    "y": meta.get("Y_COORD"),
                    "z": meta.get("Z_COORD"),
                },
                "parent_path": meta.get("PARENT_PATH"),
                "workspace": meta.get("WORKSPACE"),
                "hostname": meta.get("hostname"),
                "interfaces": block["interfaces"],
                "links": block["links"],
                "configs": _configs_to_json(block["configs"]),
            }
        )

    return report


def _build_raw_appendix(best, strings):
    lines = []
    lines.append("[packettracer_devices_raw]")
    lines.append("pid=%d" % best["pid"])
    lines.append("region=0x%x" % best["base"])
    lines.append("bytes=%d" % best["size"])
    lines.append("score=%d" % best["score"])
    if best["hits"]:
        lines.append("markers=%s" % ", ".join(best["hits"]))
    lines.append("")
    lines.append("[strings]")
    lines.extend(strings)
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def _live_dump_packet_tracer(infile, include_raw=False):
    pids = _list_packet_tracer_pids()
    if not pids:
        return None

    basename = Path(infile).name.lower().encode("ascii", "ignore")
    best = None

    for pid in pids:
        handle = _open_process(pid)
        try:
            for base, mbi in _iter_memory_regions(handle):
                if not _region_is_readable(mbi):
                    continue

                size = min(mbi.RegionSize, 2 * 1024 * 1024)
                data = _read_memory(handle, base, size)
                if not data:
                    continue

                score, hits = _score_region(data)
                if basename in data.lower():
                    score += 2

                if score <= 0:
                    continue

                if best is None or score > best["score"]:
                    best = {
                        "pid": pid,
                        "base": base,
                        "size": len(data),
                        "score": score,
                        "hits": hits,
                        "data": data,
                    }
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    if best is None:
        return None

    strings = _extract_strings(best["data"])
    if not strings:
        return None

    structured = _format_device_blocks(strings)
    report = _build_json_report(strings, best)
    raw = _build_raw_appendix(best, strings) if include_raw else b""

    if raw:
        return structured + b"\n" + raw, report
    return structured, report


def ptfile_decode(infile, outfile):
    try:
        decoded = _try_legacy_decode(infile)
        print("[*] Writing XML to '%s'" % outfile)
        with open(outfile, "wb") as f:
            f.write(decoded)
        return
    except Exception as legacy_error:
        print("[!] Legacy decode failed: %s" % legacy_error)

    include_raw = getattr(ptfile_decode, "_include_raw", False)
    live_dump = _live_dump_packet_tracer(infile, include_raw=include_raw)
    if live_dump is None:
        raise RuntimeError(
            "Could not decode '%s' with the legacy wrapper and Packet Tracer live dump was unavailable."
            % infile
        )

    print("[*] Writing live dump to '%s'" % outfile)
    if isinstance(live_dump, tuple):
        live_dump_data, report = live_dump
    else:
        live_dump_data, report = live_dump, None
    with open(outfile, "wb") as f:
        f.write(live_dump_data)

    if report is not None:
        json_outfile = str(Path(outfile).with_suffix(".json"))
        with open(json_outfile, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)


def ptfile_encode(infile, outfile):
    with open(infile, "rb") as f:
        in_data = bytearray(f.read())

    i_size = len(in_data)

    print("[*] Opening XML file '%s'" % infile)
    print("[*] File size uncompressed = %d bytes" % i_size)

    i_size = i_size.to_bytes(4, "big")

    out_data = zlib.compress(in_data)
    out_data = i_size + out_data
    o_size = len(out_data)
    print("[*] File size compressed = %d bytes" % o_size)

    xor_out = bytearray()
    for byte in out_data:
        xor_out.append((byte ^ o_size) & 0xFF)
        o_size -= 1

    print("[*] Writing PKT to '%s'" % outfile)
    with open(outfile, "wb") as f:
        f.write(xor_out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert Packet Tracer files (.pkt/.pka) to XML and vice versa"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-d",
        "--decode",
        help="Converts Packet Tracer file to XML",
        action="store_true",
    )
    group.add_argument(
        "-e",
        "--encode",
        help="Converts XML to Packet Tracer File",
        action="store_true",
    )
    parser.add_argument(
        "--include-raw",
        help="Append the raw memory string dump after the structured report",
        action="store_true",
    )
    parser.add_argument("infile", help="Packet Tracer file", action="store", type=str)
    parser.add_argument("outfile", help="Output file (XML)", action="store", type=str)

    args = parser.parse_args()

    if args.decode:
        ptfile_decode._include_raw = args.include_raw
        ptfile_decode(args.infile, args.outfile)
    elif args.encode:
        ptfile_encode(args.infile, args.outfile)
    else:
        parser.print_help()
        sys.exit(1)
