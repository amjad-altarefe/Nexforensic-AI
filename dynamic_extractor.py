import csv
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set



OUTPUT_COLUMNS = [
    "sha256",
    "label",
    "date",
    "tcp_conn",
    "udp_conn",
    "http_requests",
    "dns_requests",
    "domains_count",
    "process_count",
    "total_api_calls",
    "suspicious_api_calls",
    "files_created",
    "files_deleted",
    "dropped_office_macro_count",
    "dropped_script_count",
    "dropped_executable_count",
    "temp_suspicious_file_created",
    "pdf_extracted_embedded_payload",
    "suspicious_dropped_files_count",
    "suspicious_dropped_files",
    "registry_written",
    "registry_keys_touched",
    "unique_api_count",
    "failed_api_calls",
    "failed_api_ratio",
    "child_process_count",
    "unique_process_names",
    "has_child_process",
    "has_temp_exe_execution",
    "api_createprocess_count",
    "api_writeprocessmemory_count",
    "api_createremotethread_count",
    "api_virtualprotectex_count",
    "api_ntallocatevirtualmemory_count",
    "api_regsetvalue_count",
    "api_ldrloaddll_count",
    "api_deviceiocontrol_count",
    "hosts_count",
    "unique_dst_ports",
    "has_network_activity",
    "analysis_duration_sec",
    "api_category_system_count",
    "api_category_process_count",
    "api_category_network_count",
]

BENIGN_LABEL = 0
HTTP_PORTS = {80, 443, 8080, 8443}

PRIMARY_READER_HINTS = {"acrobat.exe", "acrord32.exe"}
NOISY_HELPER_PROCESSES = {"acrocef.exe", "rdrcef.exe"}

OFFICE_PAYLOAD_EXTS = {
    ".doc", ".docm", ".dot", ".dotm",
    ".xls", ".xlsm", ".xlt", ".xltm",
    ".ppt", ".pptm", ".pot", ".potm",
    ".rtf"
}

SCRIPT_PAYLOAD_EXTS = {
    ".js", ".jse", ".vbs", ".vbe", ".ps1",
    ".hta", ".wsf", ".bat", ".cmd"
}

EXECUTABLE_PAYLOAD_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi"
}

TEMP_MARKERS = [
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\tmp\\",
]

# فقط العمليات "المعبرة" أكثر
MEANINGFUL_FILE_OPS = {
    "createfile",
    "writefile",
    "setinformationfile",
    "setrenameinformationfile",
    "setdispositioninformationfile",
    "ntcreatefile",
}

MEANINGFUL_REGISTRY_OPS = {
    "regsetvalue",
    "regcreatekey",
    "regdeletevalue",
    "regdeletekey",
    "ntsetvaluekey",
    "ntcreatekey",
    "ntdeletekey",
}

MEANINGFUL_PROCESS_OPS = {
    "process create",
    "thread create",
    "load image",
    "createprocess",
    "writeprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "virtualprotectex",
    "ntallocatevirtualmemory",
    "process start",
}

MEANINGFUL_NETWORK_OPS = {
    "tcp send",
    "tcp receive",
    "udp send",
    "udp receive",
}

SUSPICIOUS_PROC_OPS = {
    "process create",
    "createprocess",
    "writeprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "virtualprotectex",
    "ntallocatevirtualmemory",
    "deviceiocontrol",
}

REGISTRY_WRITE_OPS = {
    "regsetvalue",
    "regcreatekey",
    "regdeletevalue",
    "regdeletekey",
    "ntsetvaluekey",
    "ntcreatekey",
    "ntdeletekey",
}

FILE_DELETE_HINTS = {
    "delete",
    "remove",
    "supersede",
}


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def read_status(job_dir: Path) -> Dict[str, Any]:
    status_path = job_dir / "status.json"
    if not status_path.exists():
        raise FileNotFoundError(f"status.json not found in {job_dir}")
    return json.loads(status_path.read_text(encoding="utf-8-sig"))


def get_date_from_status(status: Dict[str, Any]) -> str:
    started_at = normalize_text(status.get("started_at"))
    if not started_at:
        return ""
    try:
        return datetime.fromisoformat(started_at).strftime("%Y-%m-%d")
    except Exception:
        return started_at[:10]


def get_duration_from_status(status: Dict[str, Any]) -> int:
    started_at = normalize_text(status.get("started_at"))
    ended_at = normalize_text(status.get("ended_at"))

    if started_at and ended_at:
        try:
            start_dt = datetime.fromisoformat(started_at)
            end_dt = datetime.fromisoformat(ended_at)
            return int((end_dt - start_dt).total_seconds())
        except Exception:
            pass

    return safe_int(status.get("observe_seconds"), 0)


def read_procmon_rows(procmon_csv: Path) -> List[Dict[str, str]]:
    if not procmon_csv.exists():
        return []

    rows = []
    with procmon_csv.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def is_primary_reader_process(name: str) -> bool:
    name = normalize_text(name).lower()
    return name in PRIMARY_READER_HINTS


def is_noisy_helper_process(name: str) -> bool:
    name = normalize_text(name).lower()
    return name in NOISY_HELPER_PROCESSES


def is_pdf_path(path: str) -> bool:
    return normalize_text(path).lower().endswith(".pdf")


def infer_failure_from_row(row: Dict[str, str]) -> bool:
    result = normalize_text(row.get("Result", "")).lower()
    detail = normalize_text(row.get("Detail", "")).lower()

    failure_markers = [
        "name not found",
        "not found",
        "access denied",
        "buffer overflow",
        "invalid parameter",
        "end of file",
        "no such file",
        "sharing violation",
        "file locked",
        "reparse",
    ]

    return any(marker in result or marker in detail for marker in failure_markers)


def is_meaningful_procmon_op(operation: str) -> bool:
    op = normalize_text(operation).lower()
    return (
        op in MEANINGFUL_FILE_OPS
        or op in MEANINGFUL_REGISTRY_OPS
        or op in MEANINGFUL_PROCESS_OPS
        or op in MEANINGFUL_NETWORK_OPS
        or op == "deviceiocontrol"
        or op == "ldrloaddll"
    )


def select_procmon_scope(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    selected = []

    for r in rows:
        process_name = normalize_text(r.get("Process Name", "")).lower()
        operation = normalize_text(r.get("Operation", "")).lower()
        path = normalize_text(r.get("Path", "")).lower()
        detail = normalize_text(r.get("Detail", "")).lower()

        if is_noisy_helper_process(process_name):
            continue

        keep = False

        if is_primary_reader_process(process_name):
            keep = True

        if is_pdf_path(path):
            keep = True

        if "acrord32.exe" in detail or "acrobat.exe" in detail:
            keep = True

        if operation in {"process create", "createprocess"}:
            keep = True

        if keep and is_meaningful_procmon_op(operation):
            selected.append(r)

    return selected

def looks_like_exe_target(text: str) -> bool:
    text = normalize_text(text).lower()
    return text.endswith(".exe") or ".exe" in text

def is_temp_path(path: str) -> bool:
    p = normalize_text(path).lower().replace("/", "\\")
    return any(marker in p for marker in TEMP_MARKERS)


def get_file_extension(path: str) -> str:
    try:
        return Path(str(path)).suffix.lower()
    except Exception:
        return ""


def is_created_file_event(row: Dict[str, str]) -> bool:
    """
    Detects Procmon CreateFile events where a file was actually created.
    Procmon usually stores this in Detail as: OpenResult: Created
    """

    operation = normalize_text(row.get("Operation", "")).lower()
    result = normalize_text(row.get("Result", "")).lower()
    detail = normalize_text(row.get("Detail", "")).lower()

    if operation != "createfile":
        return False

    if result != "success":
        return False

    created_markers = [
        "openresult: created",
        "disposition: create",
    ]

    return any(marker in detail for marker in created_markers)


def extract_payload_drop_features(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Extracts suspicious dropped-payload evidence from Procmon rows.

    Main purpose:
    Detect cases such as:
    PDF -> Adobe Reader -> Temp -> dropped .docm / .js / .exe payload
    """

    features = {
        "dropped_office_macro_count": 0,
        "dropped_script_count": 0,
        "dropped_executable_count": 0,
        "temp_suspicious_file_created": 0,
        "pdf_extracted_embedded_payload": 0,
        "suspicious_dropped_files_count": 0,
        "suspicious_dropped_files": "",
    }

    suspicious_dropped_files: Set[str] = set()

    scoped_rows = select_procmon_scope(rows)

    if not scoped_rows:
        scoped_rows = [
            r for r in rows
            if is_primary_reader_process(normalize_text(r.get("Process Name", "")).lower())
        ]

    for row in scoped_rows:
        process_name = normalize_text(row.get("Process Name", "")).lower()
        path = normalize_text(row.get("Path", ""))

        if not path:
            continue

        if not is_created_file_event(row):
            continue

        ext = get_file_extension(path)

        is_office_payload = ext in OFFICE_PAYLOAD_EXTS
        is_script_payload = ext in SCRIPT_PAYLOAD_EXTS
        is_executable_payload = ext in EXECUTABLE_PAYLOAD_EXTS

        is_suspicious_payload = (
            is_office_payload
            or is_script_payload
            or is_executable_payload
        )

        if not is_suspicious_payload:
            continue

        suspicious_dropped_files.add(path)

        if is_office_payload:
            features["dropped_office_macro_count"] += 1

        if is_script_payload:
            features["dropped_script_count"] += 1

        if is_executable_payload:
            features["dropped_executable_count"] += 1

        if is_temp_path(path):
            features["temp_suspicious_file_created"] = 1

        if is_primary_reader_process(process_name):
            features["pdf_extracted_embedded_payload"] = 1

    features["suspicious_dropped_files_count"] = len(suspicious_dropped_files)
    features["suspicious_dropped_files"] = " | ".join(
        sorted(list(suspicious_dropped_files))[:10]
    )

    return features

def extract_procmon_features(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    scoped_rows = select_procmon_scope(rows)

    if not scoped_rows:
        scoped_rows = [
            r for r in rows
            if is_primary_reader_process(normalize_text(r.get("Process Name", "")).lower())
            and is_meaningful_procmon_op(normalize_text(r.get("Operation", "")).lower())
        ]

    if not scoped_rows:
        scoped_rows = []

    unique_process_names: Set[str] = set()
    unique_registry_keys: Set[str] = set()
    unique_ops: Set[str] = set()
    child_process_targets: Set[str] = set()

    total_api_calls = 0
    suspicious_api_calls = 0
    failed_api_calls = 0

    files_created = 0
    files_deleted = 0
    registry_written = 0

    api_createprocess_count = 0
    api_writeprocessmemory_count = 0
    api_createremotethread_count = 0
    api_virtualprotectex_count = 0
    api_ntallocatevirtualmemory_count = 0
    api_regsetvalue_count = 0
    api_ldrloaddll_count = 0
    api_deviceiocontrol_count = 0

    api_category_system_count = 0
    api_category_process_count = 0
    api_category_network_count = 0

    has_temp_exe_execution = 0

    for row in scoped_rows:
        process_name = normalize_text(row.get("Process Name", "")).lower()
        operation = normalize_text(row.get("Operation", "")).lower()
        path = normalize_text(row.get("Path", ""))
        detail = normalize_text(row.get("Detail", "")).lower()

        if not is_meaningful_procmon_op(operation):
            continue

        total_api_calls += 1

        if process_name:
            unique_process_names.add(process_name)

        if "\\temp\\" in path.lower() and path.lower().endswith(".exe"):
            has_temp_exe_execution = 1

        unique_ops.add(operation)

        if infer_failure_from_row(row):
            failed_api_calls += 1

        if operation in SUSPICIOUS_PROC_OPS:
            suspicious_api_calls += 1

        if operation in {"createfile", "ntcreatefile", "writefile"}:
            if is_pdf_path(path) or path.lower().endswith(".tmp") or "disposition: create" in detail or "created" in detail:
                files_created += 1

        if any(marker in operation for marker in FILE_DELETE_HINTS) or "delete: true" in detail:
            files_deleted += 1

        if operation in REGISTRY_WRITE_OPS:
            registry_written += 1

        upper_path = path.upper()
        if upper_path.startswith(("HKCU", "HKLM", "HKCR", "HKU")) and operation in REGISTRY_WRITE_OPS:
            unique_registry_keys.add(path)

        if operation in {"process create", "createprocess"}:
            target = ""

            if looks_like_exe_target(path):
                target = path.lower()
            elif looks_like_exe_target(detail):
                target = detail.lower()

            if target:
                api_createprocess_count += 1
                child_process_targets.add(target)

        if operation == "writeprocessmemory":
            api_writeprocessmemory_count += 1

        if operation in {"createremotethread", "ntcreatethreadex"}:
            api_createremotethread_count += 1

        if operation == "virtualprotectex":
            api_virtualprotectex_count += 1

        if operation == "ntallocatevirtualmemory":
            api_ntallocatevirtualmemory_count += 1

        if operation in {"regsetvalue", "ntsetvaluekey"}:
            api_regsetvalue_count += 1

        if operation == "ldrloaddll":
            api_ldrloaddll_count += 1

        if operation == "deviceiocontrol":
            api_deviceiocontrol_count += 1

        if operation in MEANINGFUL_PROCESS_OPS:
            api_category_process_count += 1
        elif operation in MEANINGFUL_NETWORK_OPS:
            api_category_network_count += 1
        else:
            api_category_system_count += 1

    failed_api_ratio = round(failed_api_calls / total_api_calls, 6) if total_api_calls > 0 else 0.0

    return {
        "process_count": len(unique_process_names),
        "total_api_calls": total_api_calls,
        "suspicious_api_calls": suspicious_api_calls,
        "files_created": files_created,
        "files_deleted": files_deleted,
        "registry_written": registry_written,
        "registry_keys_touched": len(unique_registry_keys),
        "unique_api_count": len(unique_ops),
        "failed_api_calls": failed_api_calls,
        "failed_api_ratio": failed_api_ratio,
        "child_process_count": len(child_process_targets),
        "unique_process_names": len(unique_process_names),
        "has_child_process": 1 if len(child_process_targets) > 0 else 0,
        "has_temp_exe_execution": has_temp_exe_execution,
        "api_createprocess_count": api_createprocess_count,
        "api_writeprocessmemory_count": api_writeprocessmemory_count,
        "api_createremotethread_count": api_createremotethread_count,
        "api_virtualprotectex_count": api_virtualprotectex_count,
        "api_ntallocatevirtualmemory_count": api_ntallocatevirtualmemory_count,
        "api_regsetvalue_count": api_regsetvalue_count,
        "api_ldrloaddll_count": api_ldrloaddll_count,
        "api_deviceiocontrol_count": api_deviceiocontrol_count,
        "api_category_system_count": api_category_system_count,
        "api_category_process_count": api_category_process_count,
        "api_category_network_count": api_category_network_count,
    }


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def extract_event_data(event_elem: ET.Element) -> Dict[str, str]:
    data = {}
    for child in event_elem.iter():
        if local_name(child.tag) == "Data":
            name = child.attrib.get("Name", "")
            if name:
                data[name] = child.text or ""
    return data


def parse_sysmon_events(sysmon_xml: Path) -> List[Dict[str, Any]]:
    if not sysmon_xml.exists():
        return []

    content = sysmon_xml.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        return []

    wrapped = f"<Events>{content}</Events>"

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        return []

    events = []
    for event_elem in root:
        event_id = 0
        provider = ""
        data = extract_event_data(event_elem)

        for child in event_elem.iter():
            tag = local_name(child.tag)
            if tag == "EventID":
                event_id = safe_int(child.text, 0)
            elif tag == "Provider":
                provider = child.attrib.get("Name", "")

        events.append({
            "event_id": event_id,
            "provider": provider,
            "data": data,
        })

    return events


def is_reader_related_sysmon_event(event: Dict[str, Any]) -> bool:
    data = event["data"]

    image = normalize_text(data.get("Image", "")).lower()
    parent_image = normalize_text(data.get("ParentImage", "")).lower()

    if any(h in image for h in NOISY_HELPER_PROCESSES):
        return False

    return any(h in image for h in PRIMARY_READER_HINTS) or any(h in parent_image for h in PRIMARY_READER_HINTS)


def extract_sysmon_features(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    scoped = [e for e in events if is_reader_related_sysmon_event(e)]
    if not scoped:
        scoped = []

    tcp_conn = 0
    udp_conn = 0
    http_requests = 0
    dns_requests = 0

    domains: Set[str] = set()
    hosts: Set[str] = set()
    dst_ports: Set[int] = set()

    child_process_images: Set[str] = set()

    for event in scoped:
        event_id = event["event_id"]
        data = event["data"]

        # Sysmon Event ID 1 = Process Create
        if event_id == 1:
            image = normalize_text(data.get("Image", "")).lower()
            parent_image = normalize_text(data.get("ParentImage", "")).lower()

            if image and image.endswith(".exe"):
                if any(h in parent_image for h in PRIMARY_READER_HINTS):
                    if not any(h in image for h in NOISY_HELPER_PROCESSES):
                        child_process_images.add(image)

        elif event_id == 3:
            protocol = normalize_text(data.get("Protocol", "")).upper()
            dst_ip = normalize_text(data.get("DestinationIp", ""))
            dst_port = safe_int(data.get("DestinationPort", 0))
            dst_host = normalize_text(data.get("DestinationHostname", "")).lower()

            if protocol == "TCP":
                tcp_conn += 1
            elif protocol == "UDP":
                udp_conn += 1

            if dst_ip:
                hosts.add(dst_ip)
            if dst_port > 0:
                dst_ports.add(dst_port)
            if dst_host:
                domains.add(dst_host)

            if protocol == "TCP" and dst_port in HTTP_PORTS:
                http_requests += 1

        elif event_id == 22:
            dns_requests += 1
            query_name = normalize_text(data.get("QueryName", "")).lower()
            if query_name:
                domains.add(query_name)

    return {
        "tcp_conn": tcp_conn,
        "udp_conn": udp_conn,
        "http_requests": http_requests,
        "dns_requests": dns_requests,
        "domains_count": len(domains),
        "hosts_count": len(hosts),
        "unique_dst_ports": len(dst_ports),
        "has_network_activity": 1 if (tcp_conn + udp_conn + dns_requests + http_requests) > 0 else 0,
        "child_process_count_sysmon": len(child_process_images),
        "api_createprocess_count_sysmon": len(child_process_images),
        "has_child_process_sysmon": 1 if len(child_process_images) > 0 else 0,
    }

def build_row(job_dir: Path) -> Dict[str, Any]:
    status = read_status(job_dir)
    procmon_rows = read_procmon_rows(job_dir / "procmon.csv")
    sysmon_events = parse_sysmon_events(job_dir / "sysmon.xml")

    procmon_features = extract_procmon_features(procmon_rows)
    sysmon_features = extract_sysmon_features(sysmon_events)
    payload_drop_features = extract_payload_drop_features(procmon_rows)

    row = {
        "sha256": normalize_text(status.get("sample_sha256", "")),
        "label": BENIGN_LABEL,
        "date": get_date_from_status(status),
        "tcp_conn": sysmon_features["tcp_conn"],
        "udp_conn": sysmon_features["udp_conn"],
        "http_requests": sysmon_features["http_requests"],
        "dns_requests": sysmon_features["dns_requests"],
        "domains_count": sysmon_features["domains_count"],
        "process_count": procmon_features["process_count"],
        "total_api_calls": procmon_features["total_api_calls"],
        "suspicious_api_calls": procmon_features["suspicious_api_calls"],
        "files_created": procmon_features["files_created"],
        "files_deleted": procmon_features["files_deleted"],
        "dropped_office_macro_count": payload_drop_features["dropped_office_macro_count"],
        "dropped_script_count": payload_drop_features["dropped_script_count"],
        "dropped_executable_count": payload_drop_features["dropped_executable_count"],
        "temp_suspicious_file_created": payload_drop_features["temp_suspicious_file_created"],
        "pdf_extracted_embedded_payload": payload_drop_features["pdf_extracted_embedded_payload"],
        "suspicious_dropped_files_count": payload_drop_features["suspicious_dropped_files_count"],
        "suspicious_dropped_files": payload_drop_features["suspicious_dropped_files"],
        "registry_written": procmon_features["registry_written"],
        "registry_keys_touched": procmon_features["registry_keys_touched"],
        "unique_api_count": procmon_features["unique_api_count"],
        "failed_api_calls": procmon_features["failed_api_calls"],
        "failed_api_ratio": procmon_features["failed_api_ratio"],
        "child_process_count": sysmon_features["child_process_count_sysmon"],
        "unique_process_names": procmon_features["unique_process_names"],
        "has_child_process": sysmon_features["has_child_process_sysmon"],
        "has_temp_exe_execution": procmon_features["has_temp_exe_execution"],
        "api_createprocess_count": sysmon_features["api_createprocess_count_sysmon"],
        "api_writeprocessmemory_count": procmon_features["api_writeprocessmemory_count"],
        "api_createremotethread_count": procmon_features["api_createremotethread_count"],
        "api_virtualprotectex_count": procmon_features["api_virtualprotectex_count"],
        "api_ntallocatevirtualmemory_count": procmon_features["api_ntallocatevirtualmemory_count"],
        "api_regsetvalue_count": procmon_features["api_regsetvalue_count"],
        "api_ldrloaddll_count": procmon_features["api_ldrloaddll_count"],
        "api_deviceiocontrol_count": procmon_features["api_deviceiocontrol_count"],
        "hosts_count": sysmon_features["hosts_count"],
        "unique_dst_ports": sysmon_features["unique_dst_ports"],
        "has_network_activity": sysmon_features["has_network_activity"],
        "analysis_duration_sec": get_duration_from_status(status),
        "api_category_system_count": procmon_features["api_category_system_count"],
        "api_category_process_count": procmon_features["api_category_process_count"],
        "api_category_network_count": procmon_features["api_category_network_count"],
    }

    if list(row.keys()) != OUTPUT_COLUMNS:
        raise ValueError("Output column mismatch.")

    return row


def save_row_csv(row: Dict[str, Any], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerow(row)


def main():
    if len(sys.argv) != 3:
        print("Usage: python benign_dynamic_extractor.py <job_output_dir> <output_csv>")
        sys.exit(1)

    job_dir = Path(sys.argv[1])
    output_csv = Path(sys.argv[2])

    if not job_dir.exists():
        raise FileNotFoundError(f"Job directory not found: {job_dir}")

    row = build_row(job_dir)
    save_row_csv(row, output_csv)

    print(f"Saved features to: {output_csv}")
    print("Columns:")
    print(", ".join(OUTPUT_COLUMNS))


if __name__ == "__main__":
    main()