import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Interface_Info:
    name: str
    ip: str = ""
    subnet: str = ""
    mac: str = ""
    power: bool = True
    bandwidth: int = 100000
    full_duplex: bool = True


@dataclass
class Device_Info:
    name: str
    device_type: str
    model: str
    interfaces: List[Interface_Info] = field(default_factory=list)
    running_config: List[str] = field(default_factory=list)
    startup_config: List[str] = field(default_factory=list)


class Topology_Model:
    def __init__(self, xml_data: bytes):
        self.root = ET.fromstring(xml_data)

    def to_xml_bytes(self) -> bytes:
        return ET.tostring(self.root, encoding="utf-8", xml_declaration=True)

    def list_devices(self) -> List[Device_Info]:
        devices = []
        for dev_elem in self.root.findall(".//DEVICES/DEVICE"):
            engine = dev_elem.find("ENGINE")
            if engine is None:
                continue

            name = engine.findtext("NAME", "Unknown")
            dtype_elem = engine.find("TYPE")
            dtype = dtype_elem.text if dtype_elem is not None else "Unknown"
            model = dtype_elem.attrib.get("model", "") if dtype_elem is not None else ""

            interfaces = []
            for port in engine.findall(".//PORT"):
                port_type = port.findtext("TYPE", "")
                ip = port.findtext("IP", "")
                subnet = port.findtext("SUBNET", "")
                mac = port.findtext("MACADDRESS", "")
                power = port.findtext("POWER", "true").lower() == "true"
                bw_text = port.findtext("BANDWIDTH", "100000")
                bandwidth = int(bw_text) if bw_text.isdigit() else 100000
                duplex = port.findtext("FULLDUPLEX", "true").lower() == "true"

                interfaces.append(
                    Interface_Info(
                        name=port_type,
                        ip=ip,
                        subnet=subnet,
                        mac=mac,
                        power=power,
                        bandwidth=bandwidth,
                        full_duplex=duplex,
                    )
                )

            rc_lines = []
            rc_elem = engine.find("RUNNINGCONFIG")
            if rc_elem is not None:
                for line in rc_elem.findall("LINE"):
                    rc_lines.append(line.text or "")

            sc_lines = []
            sc_elem = engine.find("STARTUPCONFIG")
            if sc_elem is not None:
                for line in sc_elem.findall("LINE"):
                    sc_lines.append(line.text or "")

            devices.append(
                Device_Info(
                    name=name,
                    device_type=dtype,
                    model=model,
                    interfaces=interfaces,
                    running_config=rc_lines,
                    startup_config=sc_lines,
                )
            )

        return devices

    def get_device(self, name: str) -> Optional[Device_Info]:
        for dev in self.list_devices():
            if dev.name.lower() == name.lower():
                return dev
        return None

    def set_running_config(self, device_name: str, config_lines: List[str]) -> bool:
        for dev_elem in self.root.findall(".//DEVICES/DEVICE"):
            engine = dev_elem.find("ENGINE")
            if engine is None:
                continue

            name = engine.findtext("NAME", "")
            if name.lower() != device_name.lower():
                continue

            rc_elem = engine.find("RUNNINGCONFIG")
            if rc_elem is None:
                rc_elem = ET.SubElement(engine, "RUNNINGCONFIG")

            for child in list(rc_elem):
                rc_elem.remove(child)

            for line in config_lines:
                line_elem = ET.SubElement(rc_elem, "LINE")
                line_elem.text = line

            return True
        return False

    def export_configs_to_dir(self, output_dir: str):
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        for dev in self.list_devices():
            if not dev.running_config:
                continue

            clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in dev.name)
            cfg_file = target_dir / f"{clean_name}.ios"

            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write("\n".join(dev.running_config) + "\n")
