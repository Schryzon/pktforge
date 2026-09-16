#!/usr/bin/env python3

"""pktforge: Ultra-fast offline Cisco Packet Tracer 7.x decompiler, compiler, and challenge engine."""

import argparse
import json
import sys
import time
from pathlib import Path

from pktcore.crypto.pipeline import Pkt_Pipeline
from pktcore.model.challenge import Challenge_Manager
from pktcore.model.topology import Topology_Model


def cmd_decompile(args):
    in_path = Path(args.infile)
    if not in_path.exists():
        print(f"[-] Input file not found: {in_path}")
        sys.exit(1)

    out_path = Path(args.outfile) if args.outfile else in_path.with_suffix(".xml")

    print(f"[*] Reading '{in_path}' ({in_path.stat().st_size:,} bytes)...")
    with open(in_path, "rb") as f:
        raw_pkt = f.read()

    pipeline = Pkt_Pipeline()
    engine_desc = "C-Accelerator (Sub-frame)" if pipeline.c_bridge.is_ready else "Pure Python"
    print(f"[*] Decrypting with {engine_desc}...")

    t0 = time.perf_counter()
    xml_data = pipeline.decompile(raw_pkt)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"[+] Decrypted in {elapsed_ms:.2f} ms! XML size: {len(xml_data):,} bytes")

    with open(out_path, "wb") as f:
        f.write(xml_data)
    print(f"[+] Written XML to '{out_path}'")

    if args.dump_configs:
        dump_dir = Path(args.dump_configs)
        print(f"[*] Dumping device Cisco IOS configs to '{dump_dir}'...")
        topo = Topology_Model(xml_data)
        topo.export_configs_to_dir(str(dump_dir))
        print(f"[+] Device configs exported successfully")


def cmd_compile(args):
    in_path = Path(args.infile)
    if not in_path.exists():
        print(f"[-] Input XML file not found: {in_path}")
        sys.exit(1)

    out_path = Path(args.outfile) if args.outfile else in_path.with_suffix(".pkt")

    print(f"[*] Reading XML '{in_path}' ({in_path.stat().st_size:,} bytes)...")
    with open(in_path, "rb") as f:
        xml_data = f.read()

    pipeline = Pkt_Pipeline()
    engine_desc = "C-Accelerator (Sub-frame)" if pipeline.c_bridge.is_ready else "Pure Python"
    print(f"[*] Compiling & encrypting with {engine_desc}...")

    t0 = time.perf_counter()
    pkt_data = pipeline.compile(xml_data)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    print(f"[+] Compiled in {elapsed_ms:.2f} ms! PKT size: {len(pkt_data):,} bytes")

    with open(out_path, "wb") as f:
        f.write(pkt_data)
    print(f"[+] Written Packet Tracer file to '{out_path}'")


def cmd_challenge_list(args):
    in_path = Path(args.infile)
    if not in_path.exists():
        print(f"[-] File not found: {in_path}")
        sys.exit(1)

    pipeline = Pkt_Pipeline()
    with open(in_path, "rb") as f:
        raw_pkt = f.read()

    xml_data = pipeline.decompile(raw_pkt) if not str(in_path).endswith(".xml") else raw_pkt
    mgr = Challenge_Manager(xml_data)

    notes = mgr.list_notes()
    print(f"\n=== Canvas Notes & Storyboard ({len(notes)} items) ===")
    for idx, note in enumerate(notes, 1):
        preview = note.text.replace("\n", " ")
        if len(preview) > 90:
            preview = preview[:87] + "..."
        print(f"[{idx:02d}] UUID: {note.uuid} | Pos: ({note.x}, {note.y})")
        print(f"     Text: {preview}\n")

    scenario = mgr.get_scenario_instructions()
    if scenario:
        print(f"=== Scenario Instruction ===\n{scenario}\n")

    web_pages = mgr.get_web_pages()
    if web_pages:
        print(f"=== Web Server Root Pages ({len(web_pages)} files) ===")
        for page in web_pages:
            content_preview = page["content"].replace("\n", " ")[:80]
            print(f"- [{page['device']}] {page['filename']} ({page['type']}): {content_preview}...")


def cmd_challenge_edit(args):
    in_path = Path(args.infile)
    out_path = Path(args.outfile) if args.outfile else in_path

    pipeline = Pkt_Pipeline()
    with open(in_path, "rb") as f:
        raw_pkt = f.read()

    t0 = time.perf_counter()
    xml_data = pipeline.decompile(raw_pkt)
    mgr = Challenge_Manager(xml_data)

    target_uuid = args.uuid
    if not target_uuid:
        rule_notes = mgr.get_rule_notes()
        if not rule_notes:
            print("[-] No rule set note found automatically. Please specify --uuid.")
            sys.exit(1)
        target_uuid = rule_notes[0].uuid
        print(f"[*] Auto-detected rule note UUID: {target_uuid}")

    new_text = args.text
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            new_text = f.read()

    if not new_text:
        print("[-] Please provide new text via --text or --file")
        sys.exit(1)

    updated = mgr.update_note_text(target_uuid, new_text)
    if not updated:
        print(f"[-] Note with UUID '{target_uuid}' not found.")
        sys.exit(1)

    new_xml = mgr.to_xml_bytes()
    new_pkt = pipeline.compile(new_xml)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    with open(out_path, "wb") as f:
        f.write(new_pkt)

    print(f"[+] Successfully edited challenge note and saved to '{out_path}' in {elapsed_ms:.2f} ms!")


def cmd_challenge_add(args):
    in_path = Path(args.infile)
    out_path = Path(args.outfile) if args.outfile else in_path

    pipeline = Pkt_Pipeline()
    with open(in_path, "rb") as f:
        raw_pkt = f.read()

    t0 = time.perf_counter()
    xml_data = pipeline.decompile(raw_pkt)
    mgr = Challenge_Manager(xml_data)

    new_text = args.text
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            new_text = f.read()

    note_obj = mgr.add_note(new_text, x=args.x, y=args.y)
    new_xml = mgr.to_xml_bytes()
    new_pkt = pipeline.compile(new_xml)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    with open(out_path, "wb") as f:
        f.write(new_pkt)

    print(f"[+] Added new canvas note [UUID {note_obj.uuid}] at ({args.x}, {args.y}) in {elapsed_ms:.2f} ms!")


def cmd_devices(args):
    in_path = Path(args.infile)
    if not in_path.exists():
        print(f"[-] File not found: {in_path}")
        sys.exit(1)

    pipeline = Pkt_Pipeline()
    with open(in_path, "rb") as f:
        raw_pkt = f.read()

    xml_data = pipeline.decompile(raw_pkt) if not str(in_path).endswith(".xml") else raw_pkt
    topo = Topology_Model(xml_data)

    devices = topo.list_devices()
    print(f"\n=== Network Device Inventory ({len(devices)} devices) ===")
    for dev in devices:
        ip_summary = []
        for iface in dev.interfaces:
            if iface.ip:
                ip_summary.append(f"{iface.name}: {iface.ip}/{iface.subnet}")

        ip_text = ", ".join(ip_summary) if ip_summary else "No IP assigned"
        cfg_info = f"IOS Config: {len(dev.running_config)} lines" if dev.running_config else "No IOS config"
        print(f"• [{dev.device_type}] {dev.name} ({dev.model}) | {cfg_info}")
        if ip_summary:
            print(f"    Interfaces: {ip_text}")


def main():
    parser = argparse.ArgumentParser(
        description="pktforge: Ultra-fast offline Cisco Packet Tracer 7.x decompiler, compiler & challenge suite",
    )

    # Legacy flags support
    parser.add_argument("-d", "--decode", action="store_true", help="Legacy flag: decompile .pkt to .xml")
    parser.add_argument("-e", "--encode", action="store_true", help="Legacy flag: compile .xml to .pkt")

    subparsers = parser.add_subparsers(dest="subcommand")

    # decompile
    p_decompile = subparsers.add_parser("decompile", help="Decompile .pkt/.pka to XML")
    p_decompile.add_argument("infile", help="Input Packet Tracer file (.pkt/.pka)")
    p_decompile.add_argument("-o", "--outfile", help="Output XML path")
    p_decompile.add_argument("--dump-configs", help="Directory to export all device IOS configs")

    # compile
    p_compile = subparsers.add_parser("compile", help="Compile XML to .pkt/.pka")
    p_compile.add_argument("infile", help="Input XML file")
    p_compile.add_argument("-o", "--outfile", help="Output .pkt path")

    # challenge
    p_chal = subparsers.add_parser("challenge", help="Inspect and modify challenge narrations and rulesets")
    chal_sub = p_chal.add_subparsers(dest="chal_action")

    # challenge list
    p_chal_list = chal_sub.add_parser("list", help="List all canvas notes, narrations, rules, and web pages")
    p_chal_list.add_argument("infile", help="Input .pkt file")

    # challenge edit
    p_chal_edit = chal_sub.add_parser("edit", help="Edit a canvas note or ruleset in-place and recompile")
    p_chal_edit.add_argument("infile", help="Input .pkt file")
    p_chal_edit.add_argument("-o", "--outfile", help="Output .pkt file (default: overwrite infile)")
    p_chal_edit.add_argument("--uuid", help="UUID of note to edit (auto-detects rule note if omitted)")
    p_chal_edit.add_argument("--text", help="New text content")
    p_chal_edit.add_argument("--file", help="File containing new text content")

    # challenge add
    p_chal_add = chal_sub.add_parser("add", help="Add a new canvas note/narration")
    p_chal_add.add_argument("infile", help="Input .pkt file")
    p_chal_add.add_argument("-o", "--outfile", help="Output .pkt file")
    p_chal_add.add_argument("--text", help="Text content")
    p_chal_add.add_argument("--file", help="File containing text content")
    p_chal_add.add_argument("--x", type=int, default=2000, help="Canvas X position (default: 2000)")
    p_chal_add.add_argument("--y", type=int, default=2000, help="Canvas Y position (default: 2000)")

    # devices
    p_devices = subparsers.add_parser("devices", help="List all devices, interfaces, IP addresses, and configs")
    p_devices.add_argument("infile", help="Input .pkt or .xml file")

    # Positional args for legacy support
    parser.add_argument("legacy_infile", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("legacy_outfile", nargs="?", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Legacy CLI routing
    if args.decode or (args.legacy_infile and not args.subcommand and not args.encode):
        args.infile = args.legacy_infile
        args.outfile = args.legacy_outfile
        args.dump_configs = None
        cmd_decompile(args)
        return
    elif args.encode:
        args.infile = args.legacy_infile
        args.outfile = args.legacy_outfile
        cmd_compile(args)
        return

    # Subcommand routing
    if args.subcommand == "decompile":
        cmd_decompile(args)
    elif args.subcommand == "compile":
        cmd_compile(args)
    elif args.subcommand == "challenge":
        if args.chal_action == "list":
            cmd_challenge_list(args)
        elif args.chal_action == "edit":
            cmd_challenge_edit(args)
        elif args.chal_action == "add":
            cmd_challenge_add(args)
        else:
            p_chal.print_help()
    elif args.subcommand == "devices":
        cmd_devices(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
