import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional


@dataclass
class Note_Item:
    uuid: str
    x: float
    y: float
    z: float
    text: str
    cluster_id: Optional[str] = "1-1"

    @classmethod
    def from_xml(cls, elem: ET.Element) -> "Note_Item":
        note_uuid = elem.attrib.get("uuid", f"{{{uuid.uuid4()}}}")
        x = float(elem.findtext("X", "0") or "0")
        y = float(elem.findtext("Y", "0") or "0")
        z = float(elem.findtext("Z", "0") or "0")
        text = elem.findtext("TEXT", "")
        cluster_id = elem.findtext("NOTECLUSTERID", "1-1")

        return cls(
            uuid=note_uuid,
            x=x,
            y=y,
            z=z,
            text=text,
            cluster_id=cluster_id,
        )

    def to_xml(self) -> ET.Element:
        elem = ET.Element("NOTE", {"uuid": self.uuid})

        x_elem = ET.SubElement(elem, "X")
        x_elem.text = f"{self.x:g}"

        y_elem = ET.SubElement(elem, "Y")
        y_elem.text = f"{self.y:g}"

        z_elem = ET.SubElement(elem, "Z")
        z_elem.text = f"{self.z:g}"

        text_elem = ET.SubElement(elem, "TEXT")
        text_elem.text = self.text

        cluster_elem = ET.SubElement(elem, "NOTECLUSTERID")
        cluster_elem.text = self.cluster_id or "1-1"

        return elem
