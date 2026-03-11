import csv
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


class ExtractionCancelled(Exception):
    pass


@dataclass(frozen=True)
class ExtractSpec:
    log_kind: str
    event_ids: Optional[set[int]]  # None => all


SPECS: dict[str, ExtractSpec] = {
    "security": ExtractSpec(log_kind="security", event_ids={4688}),
    "powershell_operational": ExtractSpec(log_kind="powershell_operational", event_ids={4103, 4104, 4105}),
    "sysmon": ExtractSpec(log_kind="sysmon", event_ids={1}),
}


_EVENT_ID_RE = re.compile(r"<EventID(?:\s[^>]*)?>(\d+)</EventID>")
_DATA_NAME_RE_CACHE: dict[str, re.Pattern] = {}

_TIME_CREATED_RE = re.compile(r"<TimeCreated\s+[^>]*SystemTime=\"([^\"]+)\"", flags=re.IGNORECASE)
_PROVIDER_RE = re.compile(r"<Provider\s+[^>]*Name=\"([^\"]+)\"", flags=re.IGNORECASE)
_LEVEL_RE = re.compile(r"<Level>(\d+)</Level>", flags=re.IGNORECASE)
_RECORD_ID_RE = re.compile(r"<EventRecordID>(\d+)</EventRecordID>", flags=re.IGNORECASE)
_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>", flags=re.IGNORECASE)


def _sanitize_filename(s: str) -> str:
    return re.sub(r"[\\/:*?\"<>|]", "_", s)


def _unique_path(output_dir: Path, base_name: str) -> Path:
    base_name = _sanitize_filename(base_name)
    p = output_dir / f"{base_name}.csv"
    if not p.exists():
        return p

    i = 2
    while True:
        p2 = output_dir / f"{base_name}_{i}.csv"
        if not p2.exists():
            return p2
        i += 1


def _find_evtx(folder: Path, candidates: Iterable[str]) -> Optional[Path]:
    for name in candidates:
        p1 = folder / name
        if p1.exists() and p1.is_file():
            return p1
        p2 = folder / f"{name}.evtx"
        if p2.exists() and p2.is_file():
            return p2
    return None


def find_security_evtx(folder: Path) -> Optional[Path]:
    return _find_evtx(folder, ["Security"])


def find_powershell_operational_evtx(folder: Path) -> Optional[Path]:
    return _find_evtx(
        folder,
        [
            "Microsoft-Windows-PowerShell%4Operational",
            "Microsoft-Windows-PowerShell%4Operational.evtx",
        ],
    )


def find_sysmon_operational_evtx(folder: Path) -> Optional[Path]:
    return _find_evtx(folder, ["Microsoft-Windows-Sysmon%4Operational", "Sysmon"])


def _first_machine_name(evtx_path: Path) -> Optional[str]:
    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                xml = record.xml()
                root = ET.fromstring(xml)
                computer = root.findtext("./System/Computer")
                if computer and computer.strip():
                    return computer.strip()
                break
    except Exception:
        return None
    return None


def _extract_fields(xml_text: str, include_xml: bool) -> dict:
    root = ET.fromstring(xml_text)

    def _txt(path: str) -> str:
        t = root.findtext(path)
        return t.strip() if t else ""

    event_id = _txt("./System/EventID")
    provider = root.find("./System/Provider")
    provider_name = provider.get("Name") if provider is not None else ""

    level = _txt("./System/Level")
    record_id = _txt("./System/EventRecordID")
    computer = _txt("./System/Computer")

    time_node = root.find("./System/TimeCreated")
    system_time = time_node.get("SystemTime") if time_node is not None else ""

    try:
        time_created = datetime.fromisoformat(system_time.replace("Z", "+00:00")).isoformat()
    except Exception:
        time_created = system_time

    return {
        "TimeCreated": time_created,
        "Id": int(event_id) if event_id.isdigit() else "",
        "ProviderName": provider_name,
        "Level": level,
        "MachineName": computer,
        "RecordId": int(record_id) if record_id.isdigit() else "",
        "Xml": xml_text if include_xml else "",
    }


def _extract_fields_fast(xml_text: str, include_xml: bool, event_id: Optional[int]) -> dict:
    provider = ""
    level = ""
    record_id = ""
    computer = ""
    time_created = ""

    m = _PROVIDER_RE.search(xml_text)
    if m:
        provider = m.group(1)

    m = _LEVEL_RE.search(xml_text)
    if m:
        level = m.group(1)

    m = _RECORD_ID_RE.search(xml_text)
    if m:
        record_id = m.group(1)

    m = _COMPUTER_RE.search(xml_text)
    if m:
        computer = m.group(1).strip()

    m = _TIME_CREATED_RE.search(xml_text)
    if m:
        system_time = m.group(1)
        try:
            time_created = datetime.fromisoformat(system_time.replace("Z", "+00:00")).isoformat()
        except Exception:
            time_created = system_time

    data = {
        "TimeCreated": time_created,
        "Id": event_id if isinstance(event_id, int) else "",
        "ProviderName": provider,
        "Level": level,
        "MachineName": computer,
        "RecordId": int(record_id) if record_id.isdigit() else "",
        "Xml": xml_text if include_xml else "",
    }

    if not data["TimeCreated"] or not data["ProviderName"] or not data["MachineName"] or data["Id"] == "":
        # Fallback si falta algo importante
        return _extract_fields(xml_text, include_xml=include_xml)

    return data


def _data_field_has_content(xml_text: str, field_name: str) -> bool:
    # Matches: <Data Name="CommandLine">...</Data>
    # Also supports single quotes.
    pat = _DATA_NAME_RE_CACHE.get(field_name)
    if pat is None:
        pat = re.compile(
            r"<Data\s+Name=(?:\"|')" + re.escape(field_name) + r"(?:\"|')\s*>(.*?)</Data>",
            flags=re.IGNORECASE | re.DOTALL,
        )
        _DATA_NAME_RE_CACHE[field_name] = pat

    m = pat.search(xml_text)
    if not m:
        return False

    val = m.group(1)
    if not val:
        return False
    # Remove whitespace and common XML newlines
    return bool(val.strip())


def export_evtx_to_csv(
    evtx_path: Path,
    csv_path: Path,
    allowed_ids: Optional[set[int]] = None,
    max_events: int = 0,
    include_xml: bool = True,
    detect_field_name: Optional[str] = None,
    detect_rules: Optional[list[tuple[int, str, str]]] = None,
    progress_callback: Optional[Callable[[dict], None]] = None,
    progress_every: int = 2000,
    control: Optional[dict] = None,
) -> int:
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    reviewed = 0
    detected = False
    detected_flags: dict[str, bool] = {}
    with Evtx(str(evtx_path)) as log, csv_path.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["TimeCreated", "Id", "ProviderName", "Level", "MachineName", "RecordId"]
        if include_xml:
            fieldnames.append("Xml")

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        pause_event = control.get("pause") if isinstance(control, dict) else None
        cancel_event = control.get("cancel") if isinstance(control, dict) else None

        for record in log.records():
            if cancel_event is not None and getattr(cancel_event, "is_set", None) and cancel_event.is_set():
                raise ExtractionCancelled("cancelled")
            if pause_event is not None and getattr(pause_event, "is_set", None):
                while pause_event.is_set():
                    if cancel_event is not None and getattr(cancel_event, "is_set", None) and cancel_event.is_set():
                        raise ExtractionCancelled("cancelled")
                    time.sleep(0.2)

            reviewed += 1
            xml_text = record.xml()
            eid_fast: Optional[int] = None
            if allowed_ids is not None:
                m = _EVENT_ID_RE.search(xml_text)
                if not m:
                    continue
                try:
                    eid_fast = int(m.group(1))
                except ValueError:
                    continue
                if eid_fast not in allowed_ids:
                    continue

            if detect_field_name and not detected:
                if _data_field_has_content(xml_text, detect_field_name):
                    detected = True

            if detect_rules and eid_fast is not None:
                for rule_eid, rule_field, rule_key in detect_rules:
                    if detected_flags.get(rule_key) is True:
                        continue
                    if eid_fast != rule_eid:
                        continue
                    if _data_field_has_content(xml_text, rule_field):
                        detected_flags[rule_key] = True

            # Para "raw crudo" (include_xml), evitamos parseo XML completo y usamos regex.
            data = _extract_fields_fast(xml_text, include_xml=include_xml, event_id=eid_fast)

            if not include_xml and "Xml" in data:
                data.pop("Xml", None)

            writer.writerow(data)
            count += 1

            if progress_callback and progress_every > 0 and (reviewed % progress_every == 0):
                progress_callback({"reviewed": reviewed, "exported": count})

            if max_events and count >= max_events:
                break

        if progress_callback:
            progress_callback({"reviewed": reviewed, "exported": count})

    # Store detection info on the function object for retrieval by caller without changing signature.
    export_evtx_to_csv.last_detected = detected  # type: ignore[attr-defined]
    export_evtx_to_csv.last_detected_flags = detected_flags  # type: ignore[attr-defined]
    return count


export_evtx_to_csv.last_detected = False  # type: ignore[attr-defined]
export_evtx_to_csv.last_detected_flags = {}  # type: ignore[attr-defined]


def process_input_root(
    input_root: Path,
    output_root: Path,
    max_events: int = 0,
    include_xml: bool = True,
    progress_callback: Optional[Callable[[dict], None]] = None,
    control: Optional[dict] = None,
    logs_to_process: Optional[set[str]] = None,
) -> list[dict]:
    input_root = Path(input_root)
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    created: list[dict] = []

    evidence_folders = [p for p in input_root.iterdir() if p.is_dir()]
    evidence_folders.sort(key=lambda p: p.name.lower())

    if logs_to_process is None:
        logs_to_process = {"security", "powershell", "sysmon"}

    planned_tasks = 0
    for evidence in evidence_folders:
        if "security" in logs_to_process and find_security_evtx(evidence):
            planned_tasks += 1
        if "powershell" in logs_to_process and find_powershell_operational_evtx(evidence):
            planned_tasks += 1
        if "sysmon" in logs_to_process and find_sysmon_operational_evtx(evidence):
            planned_tasks += 1

    completed_tasks = 0

    for evidence in evidence_folders:
        security = find_security_evtx(evidence) if "security" in logs_to_process else None
        psop = find_powershell_operational_evtx(evidence) if "powershell" in logs_to_process else None
        sysmon = find_sysmon_operational_evtx(evidence) if "sysmon" in logs_to_process else None

        computer = (
            _first_machine_name(security) if security else None
        ) or (
            _first_machine_name(psop) if psop else None
        ) or (
            _first_machine_name(sysmon) if sysmon else None
        ) or evidence.name

        def _report(stage: str, log_kind: str, csv_path: Optional[Path] = None, exported: Optional[int] = None) -> None:
            if not progress_callback:
                return
            payload = {
                "stage": stage,
                "evidence": evidence.name,
                "computer": computer,
                "log_kind": log_kind,
                "planned_tasks": planned_tasks,
                "completed_tasks": completed_tasks,
            }
            if csv_path is not None:
                payload["csv"] = str(csv_path)
            if exported is not None:
                payload["exported"] = exported
            progress_callback(payload)

        if security:
            _report(stage="start", log_kind="security")
            out = _unique_path(output_root, f"{computer}_{evidence.name}_security_4688")

            def _security_progress(p: dict) -> None:
                _report(stage="running", log_kind="security")
                if progress_callback:
                    progress_callback({"reviewed": p.get("reviewed", 0), "exported": p.get("exported", 0), "evidence": evidence.name, "computer": computer, "log_kind": "security", "stage": "running", "planned_tasks": planned_tasks, "completed_tasks": completed_tasks})

            exported = export_evtx_to_csv(
                security,
                out,
                allowed_ids={4688},
                max_events=max_events,
                include_xml=include_xml,
                detect_field_name="CommandLine",
                progress_callback=_security_progress,
                control=control,
            )
            cmdline_present = bool(getattr(export_evtx_to_csv, "last_detected", False))
            completed_tasks += 1
            _report(stage="done", log_kind="security", csv_path=out, exported=exported)
            created.append({"evidence": evidence.name, "computer": computer, "log": "security", "csv": str(out), "exported": exported, "cmdline_present": cmdline_present})

        if psop:
            _report(stage="start", log_kind="powershell_operational")
            out = _unique_path(output_root, f"{computer}_{evidence.name}_powershell_operational_4103_4104_4105")

            def _ps_progress(p: dict) -> None:
                _report(stage="running", log_kind="powershell_operational")
                if progress_callback:
                    progress_callback({"reviewed": p.get("reviewed", 0), "exported": p.get("exported", 0), "evidence": evidence.name, "computer": computer, "log_kind": "powershell_operational", "stage": "running", "planned_tasks": planned_tasks, "completed_tasks": completed_tasks})

            exported = export_evtx_to_csv(
                psop,
                out,
                allowed_ids={4103, 4104, 4105},
                max_events=max_events,
                include_xml=include_xml,
                detect_rules=[
                    (4104, "ScriptBlockText", "script_block_logging"),
                    (4103, "Payload", "module_logging"),
                ],
                progress_callback=_ps_progress,
                control=control,
            )
            flags = getattr(export_evtx_to_csv, "last_detected_flags", {}) or {}
            scriptblock_present = bool(flags.get("script_block_logging"))
            module_logging_present = bool(flags.get("module_logging"))
            completed_tasks += 1
            _report(stage="done", log_kind="powershell_operational", csv_path=out, exported=exported)
            created.append({"evidence": evidence.name, "computer": computer, "log": "powershell_operational", "csv": str(out), "exported": exported, "scriptblock_present": scriptblock_present, "module_logging_present": module_logging_present})

        if sysmon:
            _report(stage="start", log_kind="sysmon")
            out = _unique_path(output_root, f"{computer}_{evidence.name}_sysmon_1")

            def _sysmon_progress(p: dict) -> None:
                _report(stage="running", log_kind="sysmon")
                if progress_callback:
                    progress_callback({"reviewed": p.get("reviewed", 0), "exported": p.get("exported", 0), "evidence": evidence.name, "computer": computer, "log_kind": "sysmon", "stage": "running", "planned_tasks": planned_tasks, "completed_tasks": completed_tasks})

            exported = export_evtx_to_csv(
                sysmon,
                out,
                allowed_ids={1},
                max_events=max_events,
                include_xml=include_xml,
                progress_callback=_sysmon_progress,
                control=control,
            )
            completed_tasks += 1
            _report(stage="done", log_kind="sysmon", csv_path=out, exported=exported)
            created.append({"evidence": evidence.name, "computer": computer, "log": "sysmon", "csv": str(out), "exported": exported})

    return created
