import re
import uuid
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from pktcore.model.note import Note_Item


class Challenge_Manager:
    def __init__(self, xml_data: bytes):
        self.root = ET.fromstring(xml_data)

    def to_xml_bytes(self) -> bytes:
        return ET.tostring(self.root, encoding="utf-8", xml_declaration=True)

    def _find_or_create_notes_container(self) -> ET.Element:
        container = self.root.find(".//NOTES")
        if container is not None:
            return container

        network = self.root.find(".//NETWORK")
        if network is None:
            network = ET.SubElement(self.root, "NETWORK")

        notes_elem = ET.SubElement(network, "NOTES")
        return notes_elem

    def list_notes(self) -> List[Note_Item]:
        notes = []
        for note_elem in self.root.findall(".//NOTE"):
            notes.append(Note_Item.from_xml(note_elem))
        return notes

    def find_notes_by_regex(self, pattern: str) -> List[Note_Item]:
        regex = re.compile(pattern, re.IGNORECASE)
        matching = []

        for note in self.list_notes():
            if regex.search(note.text):
                matching.append(note)

        return matching

    def get_rule_notes(self) -> List[Note_Item]:
        keywords = ["RULE SET", "RULES", "PERATURAN", "CHALLENGE", "TASK", "TUGAS", "MODUL"]
        matching = []

        for note in self.list_notes():
            upper_text = note.text.upper()
            if any(k in upper_text for k in keywords):
                matching.append(note)

        return matching

    def update_note_text(self, note_uuid: str, new_text: str) -> bool:
        for note_elem in self.root.findall(".//NOTE"):
            elem_uuid = note_elem.attrib.get("uuid", "")
            if elem_uuid.strip("{}").lower() == note_uuid.strip("{}").lower():
                text_elem = note_elem.find("TEXT")
                if text_elem is None:
                    text_elem = ET.SubElement(note_elem, "TEXT")
                text_elem.text = new_text
                return True
        return False

    def add_note(self, text: str, x: int = 2000, y: int = 2000, z: int = 40000) -> Note_Item:
        notes_container = self._find_or_create_notes_container()
        new_uuid = f"{{{uuid.uuid4()}}}"
        note_obj = Note_Item(
            uuid=new_uuid,
            x=x,
            y=y,
            z=z,
            text=text,
            cluster_id="1-1",
        )

        note_elem = note_obj.to_xml()
        notes_container.append(note_elem)
        return note_obj

    def remove_note(self, note_uuid: str) -> bool:
        for parent in self.root.iter():
            for child in list(parent):
                if child.tag == "NOTE":
                    elem_uuid = child.attrib.get("uuid", "")
                    if elem_uuid.strip("{}").lower() == note_uuid.strip("{}").lower():
                        parent.remove(child)
                        return True
        return False

    def get_scenario_instructions(self) -> str:
        scenario = self.root.find(".//SCENARIOSET/SCENARIO")
        if scenario is None:
            return ""

        instruction = scenario.findtext("INSTRUCTION", "")
        return instruction

    def set_scenario_instructions(self, instruction_text: str):
        scenarioset = self.root.find(".//SCENARIOSET")
        if scenarioset is None:
            scenarioset = ET.SubElement(self.root, "SCENARIOSET")

        scenario = scenarioset.find("SCENARIO")
        if scenario is None:
            scenario = ET.SubElement(scenarioset, "SCENARIO")

        instruction_elem = scenario.find("INSTRUCTION")
        if instruction_elem is None:
            instruction_elem = ET.SubElement(scenario, "INSTRUCTION")

        instruction_elem.text = instruction_text

    def get_activity_ruleset(self) -> str:
        tree_checkbox = self.root.findtext(".//ANSWER_TREE_CHECK_BOX", "")
        return tree_checkbox

    def set_activity_ruleset(self, ruleset_string: str):
        elem = self.root.find(".//ANSWER_TREE_CHECK_BOX")
        if elem is not None:
            elem.text = ruleset_string

    def get_web_pages(self) -> List[Dict[str, str]]:
        pages = []
        for dev in self.root.findall(".//DEVICES/DEVICE"):
            dev_name = dev.findtext(".//NAME", "Unknown")
            for file_elem in dev.findall(".//FILE_MANAGER/FILE"):
                name = file_elem.findtext("FILE_NAME", "")
                content_elem = file_elem.find("FILE_CONTENT")
                if content_elem is not None and content_elem.text:
                    pages.append({
                        "device": dev_name,
                        "filename": name,
                        "type": content_elem.attrib.get("class", "CHttpPage"),
                        "content": content_elem.text,
                    })
        return pages

    def update_web_page(self, filename: str, new_content: str, device_name: Optional[str] = None) -> bool:
        updated = False
        for dev in self.root.findall(".//DEVICES/DEVICE"):
            dev_name = dev.findtext(".//NAME", "Unknown")
            if device_name and dev_name.lower() != device_name.lower():
                continue

            for file_elem in dev.findall(".//FILE_MANAGER/FILE"):
                name = file_elem.findtext("FILE_NAME", "")
                if name.lower() == filename.lower():
                    content_elem = file_elem.find("FILE_CONTENT")
                    if content_elem is not None:
                        content_elem.text = new_content
                        updated = True
        return updated
