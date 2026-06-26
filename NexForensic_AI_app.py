import os
from pyexpat import features
import shutil
import subprocess
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
import time
import json
import joblib
import pandas as pd
import sys
import math
from incident_correlation import correlate_incident
from forensic_report_generator import (
    generate_forensic_report,
    save_forensic_report_html,
    save_forensic_report_pdf,
    save_shap_bar_plot
)
import shap
import numpy as np
import webbrowser
from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import hashlib


# =========================================================
# CONFIG - عدلي فقط إذا لزم
# =========================================================
BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH =  str(BASE_DIR / "models" / "rf_dynamic_model.pkl")
STATIC_MODEL_PATH = str(BASE_DIR / "models" / "lgbm_static_model_v2.pkl")
STATIC_EXTRACTOR_DIR = str(BASE_DIR)

HOST_SUBMIT_SCRIPT =  str(BASE_DIR / "tools" / "host_submit_job.ps1")
# سكربت استخراج features من مجلد job output
EXTRACTOR_SCRIPT = str(BASE_DIR / "dynamic_extractor.py")

# مكان مخرجات الـ pipeline
OUTPUT_ROOT = str(BASE_DIR / "runtime_output")

# عدد ثواني المراقبة
OBSERVE_SECONDS = 90

# إذا بدك تنسخي artifacts لاسم خاص داخل مجلد منفصل
SAVE_ARTIFACTS_COPY = False
ARTIFACTS_COPY_BASE_DIR = str(BASE_DIR / "runtime_output" / "dynamic_runs")

#مسار python.exe الخاص بك، إذا كان في بيئة افتراضية أو غير موجود في PATH
PYTHON_EXE = sys.executable

IMPORTANT_DYNAMIC_FEATURES = [
    "suspicious_api_calls",
    "files_deleted",
    "dropped_office_macro_count",
    "dropped_script_count",
    "dropped_executable_count",
    "temp_suspicious_file_created",
    "pdf_extracted_embedded_payload",
    "suspicious_dropped_files_count",
    "suspicious_dropped_files",
    "unique_api_count",
    "has_temp_exe_execution",
    "api_writeprocessmemory_count",
    "api_createremotethread_count",
    "api_virtualprotectex_count",
    "api_ntallocatevirtualmemory_count",
    "api_ldrloaddll_count",
    "api_category_process_count",
    "api_category_network_count",
]

CORE_RUNTIME_FEATURES = [
    "has_temp_exe_execution",
    "api_writeprocessmemory_count",
    "api_createremotethread_count",
    "api_virtualprotectex_count",
    "api_ntallocatevirtualmemory_count",
    "api_ldrloaddll_count",
]

SUPPORTING_RUNTIME_FEATURES = [
    "suspicious_api_calls",
    "files_deleted",
    "api_category_process_count",
    "api_category_network_count",
]

DYNAMIC_DATASET_PATH = r"C:\pdf_sandbox\shared\features\dynamic_dataset_rebuilt_full.csv"

# Default mode
# False = live VM analysis
# True  = dataset replay mode
USE_DYNAMIC_DATASET_REPLAY_DEFAULT = False
USE_CAPE_JSON_DEFAULT = False

# =========================================================
# HELPERS
# =========================================================
def resource_path(relative_path):
    """
    Gets the correct resource path when running as a Python script
    or as a PyInstaller executable.
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def calculate_sha256(file_path):
    file_path = Path(file_path)

    sha256_hash = hashlib.sha256()

    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest().lower()


def extract_cape_sample_sha256(json_path):
    """
    Extracts SHA256 from common CAPEv2 JSON locations.
    Different CAPE versions may store the hash in different keys.
    """

    json_path = Path(json_path)

    with json_path.open("r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    candidates = [
        data.get("target", {}).get("file", {}).get("sha256"),
        data.get("target", {}).get("file", {}).get("sha256_hash"),
        data.get("target", {}).get("sha256"),
        data.get("sha256"),
        data.get("file", {}).get("sha256"),
        data.get("info", {}).get("sha256"),
    ]

    for value in candidates:
        if value:
            value = str(value).strip().lower()
            if len(value) == 64:
                return value

    return None


def verify_pdf_matches_cape_json(pdf_path, cape_json_path):
    pdf_sha256 = calculate_sha256(pdf_path)
    cape_sha256 = extract_cape_sample_sha256(cape_json_path)

    if not cape_sha256:
        return {
            "pdf_sha256": pdf_sha256,
            "cape_sample_sha256": "-",
            "same_sample_verification": "Unknown",
            "same_sample_reason": (
                "The CAPEv2 JSON report does not contain a readable SHA256 value, "
                "so same-sample verification could not be confirmed."
            )
        }

    if pdf_sha256 == cape_sha256:
        return {
            "pdf_sha256": pdf_sha256,
            "cape_sample_sha256": cape_sha256,
            "same_sample_verification": "Matched",
            "same_sample_reason": (
                "The selected PDF SHA256 matches the SHA256 value found in the CAPEv2 JSON report."
            )
        }

    return {
        "pdf_sha256": pdf_sha256,
        "cape_sample_sha256": cape_sha256,
        "same_sample_verification": "Not Matched",
        "same_sample_reason": (
            "The selected PDF SHA256 does not match the SHA256 value found in the CAPEv2 JSON report. "
            "The dynamic behavior should be treated as external behavioral evidence, not direct runtime evidence "
            "for the selected PDF."
        )
    }

def _cape_arg_value(call, arg_names):
    """
    Safely reads an argument value from a CAPE call object.
    """
    wanted = {str(x).lower() for x in arg_names}

    for arg in call.get("arguments", []) or []:
        name = str(arg.get("name", "")).lower()
        if name in wanted:
            return str(arg.get("value", ""))

    return ""


def extract_dynamic_features_from_cape_json(json_path):
    """
    Extracts dynamic behavioral features from a CAPEv2 JSON report
    and maps them to the same dynamic feature space used by the RF model.
    """

    json_path = Path(json_path)

    if not json_path.exists():
        raise FileNotFoundError(f"CAPE JSON report not found: {json_path}")

    with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    behavior = data.get("behavior", {}) or {}
    processes = behavior.get("processes", []) or {}
    summary = behavior.get("summary", {}) or {}
    network = data.get("network", {}) or {}

    api_counter = Counter()
    category_counter = Counter()
    process_names = set()
    failed_calls = 0
    total_calls = 0

    suspicious_api_names = {
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "NtUnmapViewOfSection",
        "CreateProcessInternalW",
        "CreateProcessW",
        "CreateProcessA",
        "WinExec",
        "ShellExecuteExW",
        "ShellExecuteW",
        "URLDownloadToFileW",
        "URLDownloadToFileA",
        "InternetOpenUrlW",
        "InternetOpenUrlA",
        "HttpSendRequestW",
        "HttpSendRequestA",
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "GetTickCount",
        "NtDelayExecution",
    }

    temp_indicators = [
        "\\temp\\",
        "\\tmp\\",
        "appdata\\local\\temp",
        "%temp%",
    ]

    has_temp_exe_execution = 0

    for proc in processes:
        pname = str(proc.get("process_name", "") or "").lower()
        ppath = str(proc.get("module_path", "") or "").lower()

        if pname:
            process_names.add(pname)

        if pname.endswith(".exe") and any(x in ppath for x in temp_indicators):
            has_temp_exe_execution = 1

        for call in proc.get("calls", []) or []:
            api = str(call.get("api", "") or "")
            category = str(call.get("category", "") or "").lower()

            if not api:
                continue

            total_calls += 1
            api_counter[api] += 1

            if category:
                category_counter[category] += 1

            if call.get("status") is False:
                failed_calls += 1

    # Summary-based file and registry features
    write_files = summary.get("write_files", []) or []
    delete_files = summary.get("delete_files", []) or []
    read_files = summary.get("read_files", []) or []
    all_files = summary.get("files", []) or []

    write_keys = summary.get("write_keys", []) or []
    delete_keys = summary.get("delete_keys", []) or []
    read_keys = summary.get("read_keys", []) or []
    all_keys = summary.get("keys", []) or []

    # Network features
    tcp_conn = len(network.get("tcp", []) or [])
    udp_conn = len(network.get("udp", []) or [])
    http_requests = len(network.get("http", []) or [])
    dns_requests = len(network.get("dns", []) or [])
    domains_count = len(network.get("domains", []) or [])
    hosts_count = len(network.get("hosts", []) or [])

    suspicious_api_calls = sum(api_counter.get(api, 0) for api in suspicious_api_names)

    features = {
        # General counts
        "process_count": len(processes),
        "unique_process_names": len(process_names),
        "total_api_calls": total_calls,
        "unique_api_count": len(api_counter),
        "failed_api_count": failed_calls,
        "failed_api_ratio": (failed_calls / total_calls) if total_calls else 0.0,

        # Important app features currently shown by your app
        "suspicious_api_calls": suspicious_api_calls,
        "files_created": len(write_files),
        "files_deleted": len(delete_files),
        "files_read": len(read_files),
        "files_touched": len(all_files),
        "registry_written": len(write_keys),
        "registry_deleted": len(delete_keys),
        "registry_read": len(read_keys),
        "registry_keys_touched": len(all_keys),
        "has_temp_exe_execution": has_temp_exe_execution,

        # API-specific counts
        "api_writeprocessmemory_count": (
            api_counter.get("WriteProcessMemory", 0)
            + api_counter.get("NtWriteVirtualMemory", 0)
        ),
        "api_createremotethread_count": (
            api_counter.get("CreateRemoteThread", 0)
            + api_counter.get("NtCreateThreadEx", 0)
        ),
        "api_virtualprotectex_count": (
            api_counter.get("VirtualProtectEx", 0)
            + api_counter.get("NtProtectVirtualMemory", 0)
        ),
        "api_ntallocatevirtualmemory_count": api_counter.get("NtAllocateVirtualMemory", 0),
        "api_ldrloaddll_count": api_counter.get("LdrLoadDll", 0),

        # Category counts
        "api_category_process_count": category_counter.get("process", 0),
        "api_category_network_count": category_counter.get("network", 0),
        "api_category_registry_count": category_counter.get("registry", 0),
        "api_category_filesystem_count": category_counter.get("filesystem", 0),
        "api_category_system_count": category_counter.get("system", 0),

        # Network counts
        "tcp_conn": tcp_conn,
        "udp_conn": udp_conn,
        "http_requests": http_requests,
        "dns_requests": dns_requests,
        "domains_count": domains_count,
        "hosts_count": hosts_count,

        # CAPE-specific context fields, useful for report/log but harmless for model alignment
        "cape_malscore": float(data.get("malscore", 0) or 0),
        "cape_detection": str(data.get("detections", "") or ""),
        "cape_package": str(data.get("info", {}).get("package", "") or ""),
        "cape_target_type": str(data.get("target", {}).get("file", {}).get("type", "") or ""),
        "cape_target_name": str(data.get("target", {}).get("file", {}).get("name", "") or ""),
    }

    return features

def run_hidden_subprocess(cmd, cwd=None, timeout=None, check=False):
    """
    Runs subprocess commands on Windows without opening PowerShell/CMD/Python console windows.
    """

    startupinfo = None
    creationflags = 0

    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        creationflags = subprocess.CREATE_NO_WINDOW

    return subprocess.run(
        cmd,
        cwd=cwd,
        timeout=timeout,
        check=check,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        startupinfo=startupinfo,
        creationflags=creationflags
    )

def run_powershell_hidden_vbs(ps_script, args_list):
    """
    Runs a PowerShell script fully hidden using a temporary VBScript launcher.
    Prevents visible PowerShell window flash.
    """

    ps_script = str(Path(ps_script).resolve())

    def ps_quote(value):
        value = str(value)
        value = value.replace('"', '\\"')
        return f'"{value}"'

    ps_args = " ".join(ps_quote(arg) for arg in args_list)

    ps_command = (
        f'powershell.exe '
        f'-NoLogo -NoProfile -NonInteractive '
        f'-ExecutionPolicy Bypass '
        f'-WindowStyle Hidden '
        f'-File {ps_quote(ps_script)} '
        f'{ps_args}'
    )

    # Escape double quotes for VBScript string
    vbs_command = ps_command.replace('"', '""')

    vbs_content = (
        'Set WshShell = CreateObject("WScript.Shell")\n'
        f'WshShell.Run "{vbs_command}", 0, True\n'
    )

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".vbs",
        delete=False,
        encoding="utf-8"
    ) as f:
        vbs_path = f.name
        f.write(vbs_content)

    try:
        return run_hidden_subprocess(
            ["wscript.exe", vbs_path],
            timeout=None
        )
    finally:
        try:
            os.remove(vbs_path)
        except Exception:
            pass

def run_command(command_list):
    result = run_hidden_subprocess(
        command_list,
        timeout=None

    )   
    return result


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
    return joblib.load(MODEL_PATH)

def load_static_components():
    if not os.path.exists(STATIC_MODEL_PATH):
        raise FileNotFoundError(f"Static model not found: {STATIC_MODEL_PATH}")

    if STATIC_EXTRACTOR_DIR not in sys.path:
        sys.path.insert(0, STATIC_EXTRACTOR_DIR)

    from feature_extractor import extract_features

    static_model = joblib.load(STATIC_MODEL_PATH)
    return static_model, extract_features


def get_static_feature_names(static_model):
    if hasattr(static_model, "feature_name_"):
        return list(static_model.feature_name_)

    if hasattr(static_model, "feature_names_in_"):
        return list(static_model.feature_names_in_)

    raise ValueError("Static model does not expose feature names.")

def explain_static_prediction(static_model, static_df, top_n=10):
    """
    Generates SHAP explanations for the static LightGBM model.

    Parameters:
        static_model:
            Trained LightGBM static model.

        static_df:
            DataFrame containing exactly one row with the static features.

        top_n:
            Number of top SHAP features to return.

    Returns:
        dict containing:
            - top_features
            - explanation_text
    """

    try:
        explainer = shap.TreeExplainer(static_model)
        shap_values = explainer.shap_values(static_df)

        # For binary classifiers, SHAP may return a list:
        # shap_values[0] for benign class
        # shap_values[1] for malicious class
        if isinstance(shap_values, list):
            values = shap_values[1][0]
        else:
            values = shap_values[0]

        feature_values = static_df.iloc[0].to_dict()
        feature_names = list(static_df.columns)

        shap_items = []

        for feature_name, shap_value in zip(feature_names, values):
            original_value = feature_values.get(feature_name, 0)

            direction = "Malicious" if shap_value > 0 else "Benign"

            shap_items.append({
                "feature": feature_name,
                "value": float(original_value),
                "shap_value": float(shap_value),
                "direction": direction,
                "abs_shap": abs(float(shap_value))
            })

        shap_items = sorted(
            shap_items,
            key=lambda item: item["abs_shap"],
            reverse=True
        )

        top_features = shap_items[:top_n]

        lines = []
        lines.append("Top Static SHAP Evidence:")

        for item in top_features:
            lines.append(
                f"- {item['feature']} = {item['value']} | "
                f"SHAP: {item['shap_value']:.4f} | "
                f"Pushes toward: {item['direction']}"
            )

        return {
            "top_features": top_features,
            "explanation_text": "\n".join(lines)
        }

    except Exception as e:
        return {
            "top_features": [],
            "explanation_text": f"Static SHAP explanation failed: {str(e)}"
        }

def explain_dynamic_prediction(dynamic_model, dynamic_df, top_n=10):
    """
    Generates SHAP explanations for the dynamic Random Forest model.

    Parameters:
        dynamic_model:
            Trained Random Forest dynamic model.

        dynamic_df:
            DataFrame containing exactly one row with the dynamic features.

        top_n:
            Number of top SHAP features to return.

    Returns:
        dict containing:
            - top_features
            - explanation_text
    """

    try:
        explainer = shap.TreeExplainer(dynamic_model)
        shap_values = explainer.shap_values(dynamic_df)

        # Binary classifier case:
        # shap_values[0] usually explains benign class
        # shap_values[1] usually explains malicious class
        if isinstance(shap_values, list):
            values = shap_values[1][0]
        else:
            values = shap_values[0]

            # بعض إصدارات SHAP ترجع array ثنائي الأبعاد
            # مثل shape = (features, classes)
            if hasattr(values, "ndim") and values.ndim > 1:
                values = values[:, 1]

        feature_values = dynamic_df.iloc[0].to_dict()
        feature_names = list(dynamic_df.columns)

        shap_items = []

        for feature_name, shap_value in zip(feature_names, values):
            original_value = feature_values.get(feature_name, 0)

            direction = "Malicious" if shap_value > 0 else "Benign"

            shap_items.append({
                "feature": feature_name,
                "value": float(original_value),
                "shap_value": float(shap_value),
                "direction": direction,
                "abs_shap": abs(float(shap_value))
            })

        shap_items = sorted(
            shap_items,
            key=lambda item: item["abs_shap"],
            reverse=True
        )

        top_features = shap_items[:top_n]

        lines = []
        lines.append("Top Dynamic SHAP Evidence:")

        for item in top_features:
            lines.append(
                f"- {item['feature']} = {item['value']} | "
                f"SHAP: {item['shap_value']:.4f} | "
                f"Pushes toward: {item['direction']}"
            )

        return {
            "top_features": top_features,
            "explanation_text": "\n".join(lines)
        }

    except Exception as e:
        return {
            "top_features": [],
            "explanation_text": f"Dynamic SHAP explanation failed: {str(e)}"
        }

def format_short_shap_summary(static_shap, top_n=5):
    top_features = static_shap.get("top_features", [])[:top_n]

    if not top_features:
        return "No SHAP explanation available."

    lines = []

    for item in top_features:
        lines.append(
            f"- {item['feature']} → {item['direction']} "
            f"(SHAP: {item['shap_value']:.2f})"
        )

    return "\n".join(lines)

def format_short_dynamic_shap_summary(dynamic_shap, top_n=5):
    top_features = dynamic_shap.get("top_features", [])[:top_n]

    if not top_features:
        return "No dynamic SHAP explanation available."

    lines = []

    for item in top_features:
        lines.append(
            f"- {item['feature']} → {item['direction']} "
            f"(SHAP: {item['shap_value']:.2f})"
        )

    return "\n".join(lines)

def predict_static_pdf(pdf_path):
    static_model, extract_features = load_static_components()

    features = extract_features(str(pdf_path))
    df = pd.DataFrame([features])

    static_features = get_static_feature_names(static_model)
    df = df.reindex(columns=static_features, fill_value=0)

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    pred = int(static_model.predict(df)[0])

    if hasattr(static_model, "predict_proba"):
        prob = float(static_model.predict_proba(df)[0][1])
    else:
        prob = 1.0 if pred == 1 else 0.0
    
    static_shap = explain_static_prediction(
        static_model=static_model,
        static_df=df,
        top_n=8
    )
    
    return {
        "static_prediction": pred,
        "static_label": "Malicious" if pred == 1 else "Benign",
        "static_probability": prob,
        "static_features": features,
        "static_shap": static_shap,
    }

def extract_feature_names_from_model(model):
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)
    raise ValueError(
        "Model does not expose feature_names_in_. "
        "Re-save the model with sklearn that stores feature names."
    )


def ensure_features_dataframe(features_dict, feature_names):
    df = pd.DataFrame([features_dict])

    for col in feature_names:
        if col not in df.columns:
            df[col] = 0

    df = df[feature_names].copy()

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def get_job_dirs(output_root: Path):
    if not output_root.exists():
        return []
    return sorted([p for p in output_root.iterdir() if p.is_dir()])


def detect_new_job_dir(before_dirs, after_dirs):
    before_set = {str(p.resolve()) for p in before_dirs}
    new_dirs = [p for p in after_dirs if str(p.resolve()) not in before_set]

    if new_dirs:
        new_dirs = sorted(new_dirs, key=lambda p: p.stat().st_mtime, reverse=True)
        return new_dirs[0]

    if after_dirs:
        after_dirs = sorted(after_dirs, key=lambda p: p.stat().st_mtime, reverse=True)
        return after_dirs[0]

    return None


def read_single_row_csv(csv_path: Path):
    df = pd.read_csv(csv_path)
    if df.empty:
        raise ValueError(f"Extractor output CSV is empty: {csv_path}")
    return df.iloc[0].to_dict()
def is_file_readable(path: Path) -> bool:
    try:
        with path.open("rb"):
            return True
    except Exception:
        return False

'''def normalize_label_value(value):
    """
    Normalizes dataset label values to malicious/benign.
    Supports numeric and text labels.
    """
    text = str(value).strip().lower()

    if text in ["1", "malicious", "malware", "true"]:
        return 1

    if text in ["0", "benign", "clean", "false"]:
        return 0
    
    return None'''

def normalize_label_value(value):
    if value is None:
        return "-"

    text = str(value).strip()

    if text.lower() in ["nan", "none", ""]:
        return "-"

    return value

def load_dynamic_replay_row(csv_path, prefer_malicious=True):
    """
    Loads one dynamic feature row from dynamic_dataset_rebuilt_full.csv.
    By default, it tries to select a malicious row.
    """

    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(f"Dynamic replay dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)

    if df.empty:
        raise ValueError("Dynamic replay dataset is empty.")

    selected_df = df

    if "label" in df.columns:
        normalized_labels = df["label"].apply(normalize_label_value)

        if prefer_malicious:
            malicious_rows = df[normalized_labels == 1]
            if not malicious_rows.empty:
                selected_df = malicious_rows
        else:
            benign_rows = df[normalized_labels == 0]
            if not benign_rows.empty:
                selected_df = benign_rows

    # Pick a random row so every test can be slightly different
    row = selected_df.sample(1).iloc[0].to_dict()

    # Remove non-feature fields
    for key in ["label", "sha256", "date", "classification_family", "classification_type"]:
        row.pop(key, None)

    return row


def run_dynamic_replay_prediction(log_callback, prefer_malicious=True):
    """
    Runs the dynamic RF model using a pre-extracted row from the dataset,
    without executing the VM pipeline.
    """

    model = load_model()
    feature_names = extract_feature_names_from_model(model)

    log_callback("[Replay Mode] Loading dynamic features from dataset...\n")

    features = load_dynamic_replay_row(
        DYNAMIC_DATASET_PATH,
        prefer_malicious=prefer_malicious
    )

    X = ensure_features_dataframe(features, feature_names)

    log_callback("[Replay Mode] Running Dynamic RF model on dataset row...\n")

    pred = int(model.predict(X)[0])
    prob = float(model.predict_proba(X)[0][1])

    dynamic_shap = explain_dynamic_prediction(
        dynamic_model=model,
        dynamic_df=X,
        top_n=8
    )

    result_label = "Malicious" if pred == 1 else "Benign"

    all_features = X.to_dict(orient="records")[0]
    important_features = filter_important_features(all_features)
    runtime_evidence = evaluate_runtime_evidence(all_features, prob)

    return {
        "prediction": pred,
        "prediction_label": result_label,
        "malicious_probability": prob,
        "features_used": all_features,
        "important_features": important_features,
        "runtime_evidence": runtime_evidence,
        "dynamic_shap": dynamic_shap,
    }

def wait_for_job_files_ready(job_dir: Path, timeout=300, poll_interval=3, stable_checks=3):
    """
    Waits until required job files exist, are readable, and their sizes remain stable.
    This prevents reading files while the VM is still copying/exporting them.
    """

    required_files = [
        job_dir / "status.json",
        job_dir / "procmon.csv",
        job_dir / "sysmon.xml",
    ]

    start = time.time()
    last_sizes = {}
    stable_count = 0

    while time.time() - start < timeout:
        missing_files = [p.name for p in required_files if not p.exists()]

        if missing_files:
            stable_count = 0
            time.sleep(poll_interval)
            continue

        all_readable = all(is_file_readable(p) for p in required_files)

        if not all_readable:
            stable_count = 0
            time.sleep(poll_interval)
            continue

        current_sizes = {}

        try:
            for p in required_files:
                current_sizes[p.name] = p.stat().st_size
        except Exception:
            stable_count = 0
            time.sleep(poll_interval)
            continue

        # Make sure files are not empty
        if any(size <= 0 for size in current_sizes.values()):
            stable_count = 0
            last_sizes = current_sizes
            time.sleep(poll_interval)
            continue

        if current_sizes == last_sizes:
            stable_count += 1
        else:
            stable_count = 0
            last_sizes = current_sizes

        if stable_count >= stable_checks:
            return True

        time.sleep(poll_interval)

    return False


def run_extractor_with_retries(extractor_cmd, extractor_csv: Path, log_callback, retries=8, delay=3):
    last_result = None

    for attempt in range(1, retries + 1):
        log_callback(f"[Extractor Attempt {attempt}/{retries}] Running extractor...\n")
        result = run_command(extractor_cmd)
        last_result = result

        log_callback("=== EXTRACTOR STDOUT ===\n")
        log_callback(result.stdout + "\n")
        log_callback("=== EXTRACTOR STDERR ===\n")
        log_callback(result.stderr + "\n")

        if result.returncode == 0 and extractor_csv.exists():
            return result

        stderr_lower = (result.stderr or "").lower()
        stdout_lower = (result.stdout or "").lower()

        lock_related = (
            "permission denied" in stderr_lower
            or "being used by another process" in stderr_lower
            or "permission denied" in stdout_lower
            or "being used by another process" in stdout_lower
        )

        if attempt < retries and lock_related:
            log_callback(f"Extractor seems blocked by file lock. Waiting {delay} seconds before retry...\n\n")
            time.sleep(delay)
            continue

        break

    return last_result
def run_dynamic_cape_json_prediction(json_path, log_callback):
    """
    Runs the dynamic RF model using extracted features from a selected CAPEv2 JSON report.
    """

    model = load_model()
    feature_names = extract_feature_names_from_model(model)

    log_callback("[CAPE JSON Mode] Extracting dynamic features from CAPEv2 report...\n")
    features = extract_dynamic_features_from_cape_json(json_path)

    log_callback("[CAPE JSON Mode] Aligning extracted features with Dynamic RF model...\n")
    X = ensure_features_dataframe(features, feature_names)

    log_callback("[CAPE JSON Mode] Running Dynamic RF model...\n")
    pred = int(model.predict(X)[0])
    prob = float(model.predict_proba(X)[0][1])

    dynamic_shap = explain_dynamic_prediction(
        dynamic_model=model,
        dynamic_df=X,
        top_n=8
    )

    result_label = "Malicious" if pred == 1 else "Benign"

    all_features = X.to_dict(orient="records")[0]

    # Keep useful CAPE metadata in the feature dict for report context
    for key in [
        "cape_malscore",
        "cape_detection",
        "cape_package",
        "cape_target_type",
        "cape_target_name",
    ]:
        if key in features:
            all_features[key] = features[key]

    important_features = filter_important_features(all_features)
    runtime_evidence = evaluate_runtime_evidence(all_features, prob)

    log_callback(f"[CAPE JSON Mode] Dynamic RF prediction: {result_label}\n")
    log_callback(f"[CAPE JSON Mode] Dynamic malicious probability: {prob:.4f}\n\n")

    return {
        "prediction": pred,
        "prediction_label": result_label,
        "malicious_probability": prob,
        "features_used": all_features,
        "important_features": important_features,
        "runtime_evidence": runtime_evidence,
        "dynamic_shap": dynamic_shap,
    }
def copy_artifacts_if_needed(job_dir: Path, pdf_path: Path):
    if not SAVE_ARTIFACTS_COPY:
        return None

    base_dir = Path(ARTIFACTS_COPY_BASE_DIR)
    base_dir.mkdir(parents=True, exist_ok=True)

    run_name = pdf_path.stem + "_artifacts"
    saved_artifacts_dir = base_dir / run_name

    if saved_artifacts_dir.exists():
        shutil.rmtree(saved_artifacts_dir)

    shutil.copytree(job_dir, saved_artifacts_dir)
    return str(saved_artifacts_dir)

def filter_important_features(features_dict):
    filtered = {}
    for key in IMPORTANT_DYNAMIC_FEATURES:
        filtered[key] = features_dict.get(key, 0)
    return filtered

def evaluate_runtime_evidence(features_dict, malicious_probability):
    core_hits = []

    for key in CORE_RUNTIME_FEATURES:
        value = float(features_dict.get(key, 0) or 0)
        if value > 0:
            core_hits.append(key)

    injection_core_features = [
        "api_writeprocessmemory_count",
        "api_createremotethread_count",
        "api_virtualprotectex_count",
        "api_ntallocatevirtualmemory_count",
        "api_ldrloaddll_count",
    ]

    injection_core_hits = []

    for key in injection_core_features:
        value = float(features_dict.get(key, 0) or 0)
        if value > 0:
            injection_core_hits.append(key)

    has_temp_exe_only = (
        "has_temp_exe_execution" in core_hits
        and len(injection_core_hits) == 0
    )

    supporting_hits = []
    payload_drop_hits = []

    suspicious_api_calls = float(features_dict.get("suspicious_api_calls", 0) or 0)
    files_deleted = float(features_dict.get("files_deleted", 0) or 0)
    process_activity = float(features_dict.get("api_category_process_count", 0) or 0)
    network_activity = float(features_dict.get("api_category_network_count", 0) or 0)
    dropped_office_macro_count = float(features_dict.get("dropped_office_macro_count", 0) or 0)
    dropped_script_count = float(features_dict.get("dropped_script_count", 0) or 0)
    dropped_executable_count = float(features_dict.get("dropped_executable_count", 0) or 0)
    temp_suspicious_file_created = float(features_dict.get("temp_suspicious_file_created", 0) or 0)
    pdf_extracted_embedded_payload = float(features_dict.get("pdf_extracted_embedded_payload", 0) or 0)


    if dropped_office_macro_count > 0:
        payload_drop_hits.append("Office macro-capable document dropped or extracted")

    if dropped_script_count > 0:
        payload_drop_hits.append("script payload dropped or extracted")

    if dropped_executable_count > 0:
        payload_drop_hits.append("executable payload dropped or extracted")

    if temp_suspicious_file_created > 0:
        supporting_hits.append("suspicious payload created in Temp directory")

    if pdf_extracted_embedded_payload > 0:
        supporting_hits.append("PDF reader extracted an embedded payload")

    if suspicious_api_calls >= 70:
        supporting_hits.append("high suspicious_api_calls")

    if files_deleted >= 10:
        supporting_hits.append("file deletion activity")

    if process_activity >= 700:
        supporting_hits.append("high process-related activity")

    if network_activity >= 250:
        supporting_hits.append("network activity observed")

    if injection_core_hits:
        verdict = "Strong Dynamic Malicious Evidence"
        explanation = (
            "High-confidence runtime malicious indicators were observed: "
            + ", ".join(injection_core_hits)
        )
    elif dropped_executable_count > 0 and temp_suspicious_file_created > 0:
        verdict = "Strong Dynamic Malicious Evidence"
        explanation = (
            "The PDF execution produced a suspicious executable payload in a temporary directory. "
            "This is strong runtime evidence of payload dropping behavior."
        )
    
    elif dropped_script_count > 0 and temp_suspicious_file_created > 0:
        verdict = "Runtime Behavior Observed - Strong Suspicion"
        explanation = (
            "The PDF execution produced a suspicious script payload in a temporary directory: "
            + ", ".join(payload_drop_hits)
        )
    
    elif dropped_office_macro_count > 0 and temp_suspicious_file_created > 0:
        verdict = "Runtime Behavior Observed - Strong Suspicion"
        explanation = (
            "The PDF execution extracted or created an Office macro-capable payload in a temporary directory. "
            "This indicates suspicious embedded payload delivery behavior."
        )
    
    elif payload_drop_hits:
        verdict = "Runtime Behavior Observed - Moderate Suspicion"
        explanation = (
            "Suspicious payload extraction behavior was observed: "
            + ", ".join(payload_drop_hits)
        )
    elif has_temp_exe_only:
        verdict = "Runtime Behavior Observed - Moderate Suspicion"
        explanation = (
            "Temporary executable execution was observed, but no process injection or memory manipulation "
            "APIs were detected. This should be reviewed by an analyst before assigning culpability."
        )
    
    elif core_hits:
        verdict = "Runtime Behavior Observed - Moderate Suspicion"
        explanation = (
            "Runtime indicators were observed, but they are not sufficient alone to confirm strong malicious execution: "
            + ", ".join(core_hits)
        )

    elif malicious_probability >= 0.05 and len(supporting_hits) >= 2:
        verdict = "Runtime Behavior Observed - Moderate Suspicion"
        explanation = (
            "No core malware APIs were observed, but multiple supporting runtime indicators exist: "
            + ", ".join(supporting_hits)
        )

    elif malicious_probability >= 0.03 and len(supporting_hits) >= 1:
        verdict = "Runtime Behavior Observed - Weak Suspicion"
        explanation = (
            "Some supporting runtime activity exists, but no strong malicious runtime indicators were observed: "
            + ", ".join(supporting_hits)
        )

    else:
        verdict = "No Strong Runtime Evidence"
        explanation = "No strong runtime malicious indicators were observed in this environment."

    return {
        "runtime_verdict": verdict,
        "runtime_explanation": explanation,
        "core_hits": core_hits + payload_drop_hits,
        "supporting_hits": supporting_hits,
    }

def evaluate_hybrid_verdict(static_result, dynamic_label, dynamic_probability, runtime_evidence):
    static_label = static_result["static_label"]
    static_probability = static_result["static_probability"]
    runtime_verdict = runtime_evidence["runtime_verdict"]

    if static_label == "Malicious" and runtime_verdict == "Strong Dynamic Malicious Evidence":
        verdict = "Malicious - Static and Dynamic Evidence"
        explanation = (
            "The static model classified the PDF as malicious, and strong runtime malicious indicators "
            "were observed during dynamic analysis."
        )
        color = "red"

    elif static_label == "Malicious" and runtime_verdict in [
        "Runtime Behavior Observed - Strong Suspicion",
        "Runtime Behavior Observed - Moderate Suspicion",
        "Runtime Behavior Observed - Weak Suspicion",
    ]:
        if runtime_verdict == "Runtime Behavior Observed - Strong Suspicion":
            verdict = "Likely Malicious - Suspicious Payload Extraction Observed"
            explanation = (
                "The static model classified the PDF as malicious, and dynamic analysis observed "
                "suspicious embedded payload extraction behavior."
            )
        else:
            verdict = "Likely Malicious - Runtime Evidence Observed"
            explanation = (
                "The static model classified the PDF as malicious. Dynamic analysis did not observe core malware APIs, "
                "but suspicious runtime activity was observed."
            )
        color = "red"

    elif static_label == "Malicious" and runtime_verdict == "No Strong Runtime Evidence":
        verdict = "Dormant Malicious (Evasive or Non-Triggered Payload)"
        explanation = (
            "The PDF contains strong structural indicators of malicious intent, "
            "but no runtime behavior was observed. This may indicate an evasive sample "
            "or a payload that did not execute in the current environment."
        )
        color = "darkorange"
        color = "darkorange"

    elif static_label == "Benign" and runtime_verdict == "Strong Dynamic Malicious Evidence":
        verdict = "Suspicious - Dynamic Evidence Overrides Static"
        explanation = (
            "The static model classified the file as benign, but strong runtime malicious indicators were observed."
        )
        color = "red"

    elif static_label == "Benign" and runtime_verdict in [
        "Runtime Behavior Observed - Moderate Suspicion",
        "Runtime Behavior Observed - Weak Suspicion",
    ]:
        verdict = "Review Needed - Runtime Suspicion"
        explanation = (
            "The static model classified the PDF as benign, but dynamic analysis observed suspicious runtime activity."
        )
        color = "orange"

    else:
        verdict = "Benign - No Strong Evidence"
        explanation = (
            "Both static and dynamic analysis did not observe strong malicious indicators."
        )
        color = "green"

    return {
        "hybrid_verdict": verdict,
        "hybrid_explanation": explanation,
        "hybrid_color": color,
        "static_label": static_label,
        "static_probability": static_probability,
        "dynamic_label": dynamic_label,
        "dynamic_probability": dynamic_probability,
        "runtime_verdict": runtime_verdict,
    }

def predict_pdf(
    pdf_path,
    log_callback,
    reported_incident_type="unknown",
    use_cape_json_dynamic=False,
    cape_json_path=None,
):
    model = load_model()
    feature_names = extract_feature_names_from_model(model)

    pdf_path = Path(pdf_path).resolve()
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    log_callback("[0/4] Running static analysis...\n")
    static_result = predict_static_pdf(pdf_path)
    log_callback(f"Static prediction: {static_result['static_label']}\n")
    log_callback(f"Static malicious probability: {static_result['static_probability']:.4f}\n\n")

    if use_cape_json_dynamic:
        if not cape_json_path:
            raise ValueError("CAPE JSON Dynamic Input is enabled, but no JSON report was selected.")

        same_sample_info = verify_pdf_matches_cape_json(
            pdf_path=pdf_path,
            cape_json_path=cape_json_path
        )

        log_callback("[CAPE JSON Mode] VM dynamic pipeline will be skipped.\n")
        log_callback("[CAPE JSON Mode] Static analysis is extracted from the selected PDF.\n")
        log_callback("[CAPE JSON Mode] Dynamic behavior is extracted from the selected CAPEv2 JSON report.\n")
        log_callback(f"[CAPE JSON Mode] PDF SHA256: {same_sample_info['pdf_sha256']}\n")
        log_callback(f"[CAPE JSON Mode] CAPE SHA256: {same_sample_info['cape_sample_sha256']}\n")
        log_callback(f"[CAPE JSON Mode] Same Sample Verification: {same_sample_info['same_sample_verification']}\n")
        log_callback(f"[CAPE JSON Mode] Verification Note: {same_sample_info['same_sample_reason']}\n\n")

        dynamic_result = run_dynamic_cape_json_prediction(
            json_path=cape_json_path,
            log_callback=log_callback
        )

        label = dynamic_result["prediction_label"]
        prob = dynamic_result["malicious_probability"]
        runtime_evidence = dynamic_result["runtime_evidence"]
        dynamic_shap = dynamic_result["dynamic_shap"]
        all_features = dynamic_result["features_used"]
        important_features = dynamic_result["important_features"]

        hybrid_result = evaluate_hybrid_verdict(
            static_result=static_result,
            dynamic_label=label,
            dynamic_probability=prob,
            runtime_evidence=runtime_evidence,
        )

        incident_correlation = correlate_incident(
            dynamic_features=all_features,
            static_result=static_result,
            hybrid_result=hybrid_result,
            reported_incident_type=reported_incident_type
        )
        incident_correlation["analysis_mode"] = "CAPE JSON Dynamic Input"
        incident_correlation["same_sample_verification"] = same_sample_info["same_sample_verification"]
        incident_correlation["same_sample_reason"] = same_sample_info["same_sample_reason"]
        incident_correlation["pdf_sha256"] = same_sample_info["pdf_sha256"]
        incident_correlation["cape_sample_sha256"] = same_sample_info["cape_sample_sha256"]
        
        replay_output_root = Path(OUTPUT_ROOT) / "cape_json_runs"
        replay_output_root.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        job_dir = replay_output_root / f"cape_json_{timestamp}"
        job_dir.mkdir(parents=True, exist_ok=True)

        preliminary_result = {
            "prediction": dynamic_result["prediction"],
            "prediction_label": label,
            "malicious_probability": prob,
            "features_used": all_features,
            "important_features": important_features,
            "runtime_evidence": runtime_evidence,
            "static_result": static_result,
            "hybrid_result": hybrid_result,
            "incident_correlation": incident_correlation,
            "dynamic_shap": dynamic_shap,
            "job_dir": str(job_dir),
            "saved_artifacts_dir": None,
            "analysis_mode": "CAPE JSON Dynamic Input",
            "cape_json_path": str(cape_json_path),
            "pdf_sha256": same_sample_info["pdf_sha256"],
            "cape_sample_sha256": same_sample_info["cape_sample_sha256"],
            "same_sample_verification": same_sample_info["same_sample_verification"],
            "same_sample_reason": same_sample_info["same_sample_reason"],
        }
        
        static_shap_plot_path = save_shap_bar_plot(
            shap_result=static_result.get("static_shap", {}),
            output_path=job_dir / "static_shap_plot.png",
            title="Static SHAP Feature Impact"
        )

        dynamic_shap_plot_path = save_shap_bar_plot(
            shap_result=dynamic_shap,
            output_path=job_dir / "dynamic_shap_plot.png",
            title="Dynamic SHAP Feature Impact"
        )

        preliminary_result["static_shap_plot_path"] = static_shap_plot_path
        preliminary_result["dynamic_shap_plot_path"] = dynamic_shap_plot_path

        forensic_report_text = generate_forensic_report(
            result=preliminary_result,
            pdf_path=str(pdf_path),
            analyst_name="NexForensic AI",
            observe_seconds=0
        )

        forensic_report_html_path = save_forensic_report_html(
            report_text=forensic_report_text,
            output_dir=job_dir,
            filename="forensic_report.html",
            static_plot_path=static_shap_plot_path,
            dynamic_plot_path=dynamic_shap_plot_path
        )

        forensic_report_pdf_path = save_forensic_report_pdf(
            report_text=forensic_report_text,
            output_dir=job_dir,
            filename="forensic_report.pdf",
            static_plot_path=static_shap_plot_path,
            dynamic_plot_path=dynamic_shap_plot_path
        )

        preliminary_result["forensic_report_text"] = forensic_report_text
        preliminary_result["forensic_report_html_path"] = forensic_report_html_path
        preliminary_result["forensic_report_pdf_path"] = forensic_report_pdf_path

        return preliminary_result
    
    output_root = Path(OUTPUT_ROOT)
    output_root.mkdir(parents=True, exist_ok=True)

    before_dirs = get_job_dirs(output_root)

    log_callback(f"[1/4] Running host dynamic pipeline on:\n{pdf_path}\n\n")

    pipeline_cmd = [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", HOST_SUBMIT_SCRIPT,
        "-SamplePath", str(pdf_path),
        "-ObserveSeconds", str(OBSERVE_SECONDS),
    ]

    pipeline_result = run_powershell_hidden_vbs(
        HOST_SUBMIT_SCRIPT,
        [
            "-SamplePath", str(pdf_path),
            "-ObserveSeconds", str(OBSERVE_SECONDS),
        ]
    )

    log_callback("=== PIPELINE STDOUT ===\n")
    log_callback(pipeline_result.stdout + "\n")
    log_callback("=== PIPELINE STDERR ===\n")
    log_callback(pipeline_result.stderr + "\n")

    if pipeline_result.returncode != 0:
        raise RuntimeError(
            f"Dynamic pipeline failed with code {pipeline_result.returncode}."
        )

    after_dirs = get_job_dirs(output_root)
    job_dir = detect_new_job_dir(before_dirs, after_dirs)

    if job_dir is None or not job_dir.exists():
        raise RuntimeError("Could not detect the generated job output folder.")

    log_callback("[2/4] Dynamic pipeline finished.\n")
    log_callback(f"Detected job directory:\n{job_dir}\n\n")
    
    log_callback("Waiting for job files to be fully released...\n")

    ready = wait_for_job_files_ready(
        job_dir,
        timeout=300,
        poll_interval=3,
        stable_checks=3
    )

    if not ready:
        raise RuntimeError(
            "Job files were not ready in time. procmon.csv / sysmon.xml / status.json may still be copying or locked."
        )

    log_callback("Job files look ready and stable.\n\n")
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir = Path(tmp_dir)
        extractor_csv = tmp_dir / "dynamic_features.csv"
    
        extractor_cmd = [
            PYTHON_EXE,
            EXTRACTOR_SCRIPT,
            str(job_dir),
            str(extractor_csv),
        ]
    
        log_callback("[3/4] Running dynamic feature extractor...\n")
    
        extractor_result = run_extractor_with_retries(
            extractor_cmd,
            extractor_csv,
            log_callback,
            retries=8,
            delay=3
        )
    
        if extractor_result.returncode != 0:
            raise RuntimeError(
                f"Feature extractor failed with code {extractor_result.returncode}."
            )
    
        if not extractor_csv.exists():
            raise RuntimeError("Extractor did not generate the expected CSV output.")
    
        features = read_single_row_csv(extractor_csv)

        features.pop("label", None)
        features.pop("sha256", None)
        features.pop("date", None)

        # Keep raw extractor features for forensic rules and report.
        # Some new features are not part of the trained RF model.
        raw_features = dict(features)

        X = ensure_features_dataframe(features, feature_names)

        log_callback("[4/4] Running model prediction...\n")

        pred = int(model.predict(X)[0])
        prob = float(model.predict_proba(X)[0][1])
        
        dynamic_shap = explain_dynamic_prediction(
            dynamic_model=model,
            dynamic_df=X,
            top_n=8
        )
        
        result_label = "Malicious" if pred == 1 else "Benign"
        saved_artifacts_dir = copy_artifacts_if_needed(job_dir, pdf_path)
        
        model_features = X.to_dict(orient="records")[0]

        all_features = dict(model_features)
        all_features.update(raw_features)

        important_features = filter_important_features(all_features)
        runtime_evidence = evaluate_runtime_evidence(all_features, prob)

        hybrid_result = evaluate_hybrid_verdict(
            static_result=static_result,
            dynamic_label=result_label,
            dynamic_probability=prob,
            runtime_evidence=runtime_evidence,
        )
        incident_correlation = correlate_incident(
            dynamic_features=all_features,
            static_result=static_result,
            hybrid_result=hybrid_result,
            reported_incident_type=reported_incident_type
        )

        preliminary_result = {
            "prediction": pred,
            "prediction_label": result_label,
            "malicious_probability": prob,
            "features_used": all_features,
            "important_features": important_features,
            "runtime_evidence": runtime_evidence,
            "static_result": static_result,
            "hybrid_result": hybrid_result,
            "incident_correlation": incident_correlation,
            "dynamic_shap": dynamic_shap,
            "job_dir": str(job_dir),
            "saved_artifacts_dir": saved_artifacts_dir,
        }

        forensic_report_text = generate_forensic_report(
            result=preliminary_result,
            pdf_path=str(pdf_path),
            analyst_name="NexForensic AI",
            observe_seconds=OBSERVE_SECONDS
        )

        static_shap_plot_path = save_shap_bar_plot(
            shap_result=static_result.get("static_shap", {}),
            output_path=Path(job_dir) / "static_shap_plot.png",
            title="Static SHAP Feature Impact"
        )
        
        dynamic_shap_plot_path = save_shap_bar_plot(
            shap_result=dynamic_shap,
            output_path=Path(job_dir) / "dynamic_shap_plot.png",
            title="Dynamic SHAP Feature Impact"
        )
        
        # Add plot paths before generating the report text
        preliminary_result["static_shap_plot_path"] = static_shap_plot_path
        preliminary_result["dynamic_shap_plot_path"] = dynamic_shap_plot_path
        
        # Temporary expected paths before saving reports
        preliminary_result["forensic_report_html_path"] = str(Path(job_dir) / "forensic_report.html")
        preliminary_result["forensic_report_pdf_path"] = str(Path(job_dir) / "forensic_report.pdf")
        
        forensic_report_html_path = save_forensic_report_html(
            report_text=forensic_report_text,
            output_dir=job_dir,
            filename="forensic_report.html",
            static_plot_path=static_shap_plot_path,
            dynamic_plot_path=dynamic_shap_plot_path
        )
        
        forensic_report_pdf_path = save_forensic_report_pdf(
            report_text=forensic_report_text,
            output_dir=job_dir,
            filename="forensic_report.pdf",
            static_plot_path=static_shap_plot_path,
            dynamic_plot_path=dynamic_shap_plot_path
        )
        
        preliminary_result["forensic_report_html_path"] = forensic_report_html_path
        preliminary_result["forensic_report_pdf_path"] = forensic_report_pdf_path
        
        return preliminary_result

# =========================================================
# UI THEME
# =========================================================
'''
UI_COLORS = {
    "bg": "#f4f1ec",
    "card": "#fffaf2",
    "card_alt": "#fcf8f2",
    "border": "#d6c4a6",
    "primary": "#5a3e1b",
    "primary_dark": "#3d2a12",
    "accent": "#b08a52",
    "success": "#16803c",
    "warning": "#d98200",
    "danger": "#c62828",
    "info": "#1f5f99",
    "text": "#1f1f1f",
    "muted": "#6f6250",
    "button_bg": "#eadfce",
    "button_active": "#d8c6aa",
    "input": "#13243A",
    "button": "#122A45",
}
'''
# =========================================================
# UI THEME - Dark Navy Cybersecurity Theme
# =========================================================

UI_COLORS = {
    "bg": "#07111f",              # Main dark navy background
    "card": "#0f1c2e",            # Card background
    "card_alt": "#13243a",        # Slightly lighter panel
    "border": "#223a5a",          # Subtle blue border

    "primary": "#38bdf8",         # Cyan blue accent
    "primary_dark": "#0ea5e9",    # Stronger cyan/blue
    "accent": "#60a5fa",          # Soft blue accent

    "success": "#22c55e",         # Green
    "warning": "#f59e0b",         # Amber
    "danger": "#ef4444",          # Red
    "info": "#38bdf8",            # Cyan info

    "text": "#e5edf7",            # Main light text
    "muted": "#94a3b8",           # Muted gray-blue text

    "button_bg": "#13243a",       # Secondary button bg
    "button_active": "#1e3a5f",   # Secondary hover
    "log_bg": "#020617",          # Terminal dark background
    "log_fg": "#dbeafe",          # Terminal text
}

# =========================================================
# UI
# =========================================================

class DynamicTestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NexForensic AI - PDF Malware Forensic Analysis")
        self.set_app_icon()
        self.root.geometry("1050x720")
        self.root.minsize(920, 620)
        self.root.configure(bg=UI_COLORS["bg"])

        self.selected_pdf = tk.StringVar()
        self.selected_cape_json = tk.StringVar()
        self.use_cape_json_dynamic = tk.BooleanVar(value=False)

        self.use_cape_json_dynamic = tk.BooleanVar(value=USE_CAPE_JSON_DEFAULT)

        self.reported_incident_type = tk.StringVar(value="unknown")

        self.last_pdf_report_path = None

        self.setup_styles()
        self.build_layout()

    def set_app_icon(self, window=None):
        if window is None:
            window = self.root

        try:
            icon_path = resource_path("nexforensic_ai_icon.ico")
            window.iconbitmap(icon_path)
        except Exception:
            pass

    def setup_styles(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Main.TFrame",
            background=UI_COLORS["bg"]
        )

        style.configure(
            "Card.TFrame",
            background=UI_COLORS.get("card", UI_COLORS["bg"]),
            relief="flat"
        )

        style.configure(
            "Header.TLabel",
            background=UI_COLORS["bg"],
            foreground=UI_COLORS["primary"],
            font=("Segoe UI", 24, "bold")
        )

        style.configure(
            "SubHeader.TLabel",
            background=UI_COLORS["bg"],
            foreground=UI_COLORS["muted"],
            font=("Segoe UI", 10)
        )

        style.configure(
            "Section.TLabel",
            background=UI_COLORS["card"],
            foreground=UI_COLORS["primary"],
            font=("Segoe UI", 14, "bold")
        )

        style.configure(
            "Normal.TLabel",
            background=UI_COLORS["card"],
            foreground=UI_COLORS["text"],
            font=("Segoe UI", 10)
        )

        style.configure(
            "Muted.TLabel",
            background=UI_COLORS["card"],
            foreground=UI_COLORS["muted"],
            font=("Segoe UI", 9)
        )

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 9),
            background=UI_COLORS["primary_dark"],
            foreground="#ffffff",
            bordercolor=UI_COLORS["primary_dark"],
            lightcolor=UI_COLORS["primary_dark"],
            darkcolor=UI_COLORS["primary_dark"]
        )

        style.map(
            "Primary.TButton",
            background=[
                ("active", UI_COLORS["primary"]),
                ("disabled", "#334155")
            ],
            foreground=[
                ("disabled", "#94a3b8")
            ]
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(14, 9),
            background=UI_COLORS["button_bg"],
            foreground=UI_COLORS["text"],
            bordercolor=UI_COLORS["border"],
            lightcolor=UI_COLORS["button_bg"],
            darkcolor=UI_COLORS["button_bg"]
        )

        style.map(
            "Secondary.TButton",
            background=[
                ("active", UI_COLORS["button_active"]),
                ("disabled", "#1e293b")
            ],
            foreground=[
                ("disabled", "#64748b")
            ]
        )

        style.configure(
            "TEntry",
            fieldbackground=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            background=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            foreground=UI_COLORS["text"],
            insertcolor=UI_COLORS["text"],
            bordercolor=UI_COLORS["border"],
            lightcolor=UI_COLORS["border"],
            darkcolor=UI_COLORS["border"],
            padding=7
        )

        style.configure(
            "TCombobox",
            fieldbackground=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            background=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            foreground=UI_COLORS["text"],
            arrowcolor=UI_COLORS["primary"],
            bordercolor=UI_COLORS["border"],
            lightcolor=UI_COLORS["border"],
            darkcolor=UI_COLORS["border"],
            padding=7
        )

        style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", UI_COLORS.get("card_alt", UI_COLORS["card"]))
            ],
            foreground=[
                ("readonly", UI_COLORS["text"])
            ],
            background=[
                ("readonly", UI_COLORS.get("card_alt", UI_COLORS["card"]))
            ]
        )

    def browse_cape_json(self):
        path = filedialog.askopenfilename(
            title="Select CAPE JSON Report",
            filetypes=[
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )

        if path:
            self.selected_cape_json.set(path)

    def toggle_cape_json_input(self):
        """
        Enables CAPE JSON input only when CAPE JSON Dynamic Input mode is selected.
        """
        enabled = self.use_cape_json_dynamic.get()

        state = "normal" if enabled else "disabled"

        self.cape_json_entry.config(state=state)
        self.browse_cape_btn.config(state=state)

        print("CAPE JSON checkbox state:", enabled)

        if not enabled:
            self.selected_cape_json.set("")

    def build_layout(self):
        # Scrollable root container
        outer = tk.Frame(self.root, bg=UI_COLORS["bg"])
        outer.pack(fill="both", expand=True)

        self.main_canvas = tk.Canvas(
            outer,
            bg=UI_COLORS["bg"],
            highlightthickness=0
        )
        self.main_canvas.pack(side="left", fill="both", expand=True)

        self.main_scrollbar = ttk.Scrollbar(
            outer,
            orient="vertical",
            command=self.main_canvas.yview
        )
        self.main_scrollbar.pack(side="right", fill="y")

        self.main_canvas.configure(yscrollcommand=self.main_scrollbar.set)

        main = ttk.Frame(self.main_canvas, style="Main.TFrame")

        self.main_window = self.main_canvas.create_window(
            (0, 0),
            window=main,
            anchor="nw"
        )

        def on_frame_configure(event):
            self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

        def on_canvas_configure(event):
            self.main_canvas.itemconfig(self.main_window, width=event.width)

        main.bind("<Configure>", on_frame_configure)
        self.main_canvas.bind("<Configure>", on_canvas_configure)

        # Mouse wheel support
        def _on_mousewheel(event):
            self.main_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self.main_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Inner spacing
        main.configure(padding=(18, 16, 18, 16))

        # Header
        header_frame = ttk.Frame(main, style="Main.TFrame")
        header_frame.pack(fill="x", pady=(0, 14))

        title = ttk.Label(
            header_frame,
            text="NexForensic AI",
            style="Header.TLabel"
        )
        title.pack(anchor="w")

        subtitle = ttk.Label(
            header_frame,
            text="Secure PDF Malware Intelligence • Hybrid AI Detection • Forensic Correlation",
            style="SubHeader.TLabel"
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        # Input card
        input_card = self.create_card(main)
        input_card.pack(fill="x", pady=(0, 12))

        ttk.Label(
            input_card,
            text="Evidence Input",
            style="Section.TLabel"
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(14, 8))

        ttk.Label(
            input_card,
            text="Selected PDF:",
            style="Normal.TLabel"
        ).grid(row=1, column=0, sticky="w", padx=16, pady=6)

        self.pdf_entry = ttk.Entry(
            input_card,
            textvariable=self.selected_pdf,
            font=("Segoe UI", 10)
        )
        self.pdf_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=6)

        browse_btn = ttk.Button(
            input_card,
            text="Browse",
            command=self.browse_pdf,
            style="Secondary.TButton"
        )
        browse_btn.grid(row=1, column=2, sticky="e", padx=(0, 16), pady=6)

        ttk.Label(
            input_card,
            text="Reported Incident Type:",
            style="Normal.TLabel"
        ).grid(row=2, column=0, sticky="w", padx=16, pady=(6, 16))

        self.incident_combo = ttk.Combobox(
            input_card,
            textvariable=self.reported_incident_type,
            state="readonly",
            values=[
            "unknown",
            "data_loss_or_missing_files",
            "unauthorized_file_modification",
            "suspicious_file_creation",
            "data_exfiltration_suspected",
            "unauthorized_network_activity",
            "credential_theft_suspected",
            "unauthorized_access",
            "persistence_suspected",
            "malware_execution_suspected",
            "process_injection_suspected",
            "suspicious_process_activity",
            "system_configuration_change",
            "registry_modification_suspected",
            "phishing_or_social_engineering",
            "payload_delivery_suspected",
            "ransomware_like_activity",
        ],
            width=28
        )
        self.incident_combo.selection_clear()
        self.incident_combo.grid(row=2, column=1, sticky="w", padx=(0, 10), pady=(6, 16))

        input_card.columnconfigure(1, weight=1)

        # Action card
        action_card = self.create_card(main)
        action_card.pack(fill="x", pady=(0, 12))

        ttk.Label(
            action_card,
            text="Analysis Controls",
            style="Section.TLabel"
        ).pack(anchor="w", padx=16, pady=(14, 8))

        btn_frame = ttk.Frame(action_card, style="Card.TFrame")
        btn_frame.pack(fill="x", padx=16, pady=(0, 16))

        self.run_btn = ttk.Button(
            btn_frame,
            text="Run Analysis",
            command=self.run_analysis_thread,
            style="Primary.TButton"
        )
        self.run_btn.pack(side="left", padx=(0, 8))
        
        clear_btn = ttk.Button(
            btn_frame,
            text="Clear Log",
            command=self.clear_log,
            style="Secondary.TButton"
        )
        clear_btn.pack(side="left", padx=(0, 8))
       
        self.open_pdf_report_btn = ttk.Button(
            btn_frame,
            text="Open PDF Report",
            command=self.open_pdf_report,
            style="Secondary.TButton",
            state="disabled"
        )
        self.open_pdf_report_btn.pack(side="left", padx=(0, 8))

        self.cape_json_check = tk.Checkbutton(
            btn_frame,
            text="Use External JSON Dynamic Input",
            variable=self.use_cape_json_dynamic,
            command=self.toggle_cape_json_input,
            bg=UI_COLORS["card"],
            fg=UI_COLORS["text"],
            selectcolor=UI_COLORS.get("card_alt", "#0B1626"),
            activebackground=UI_COLORS["card"],
            activeforeground=UI_COLORS.get("primary", "#21C7FF"),
            font=("Segoe UI", 10, "bold")
        )
        self.cape_json_check.pack(anchor="w", padx=16, pady=(10, 6))
        
        # CAPE JSON Report row
        tk.Label(
            input_card,
            text="CAPE JSON Report:",
            bg=UI_COLORS["card"],
            fg=UI_COLORS["text"],
            font=("Segoe UI", 10, "bold")
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(10, 12))

        self.cape_json_entry = tk.Entry(
            input_card,
            textvariable=self.selected_cape_json,
            bg=UI_COLORS.get("input", "#13243A"),
            fg=UI_COLORS["text"],
            disabledbackground=UI_COLORS.get("input", "#13243A"),
            disabledforeground=UI_COLORS.get("muted", "#8FA7C2"),
            insertbackground=UI_COLORS["text"],
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightbackground=UI_COLORS.get("border", "#1E4568"),
            highlightcolor=UI_COLORS.get("primary", "#21C7FF"),
            font=("Segoe UI", 10),
            state="disabled"
        )
        self.cape_json_entry.grid(row=3, column=1, sticky="ew", padx=10, pady=(10, 12))

        self.browse_cape_btn = tk.Button(
            input_card,
            text="Browse JSON",
            command=self.browse_cape_json,
            bg=UI_COLORS.get("button", "#122A45"),
            fg=UI_COLORS["text"],
            activebackground=UI_COLORS.get("primary", "#21C7FF"),
            activeforeground="white",
            disabledforeground=UI_COLORS.get("muted", "#8FA7C2"),
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            state="disabled"
        )
        self.browse_cape_btn.grid(row=3, column=2, sticky="ew", padx=16, pady=(10, 12))

        # Result card
        result_card = self.create_card(main)
        result_card.pack(fill="x", pady=(0, 12))

        ttk.Label(
            result_card,
            text="Analysis Summary",
            style="Section.TLabel"
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(14, 8))

        self.result_label = tk.Label(
            result_card,
            text="Final Verdict: -",
            font=("Segoe UI", 14, "bold"),
            fg=UI_COLORS["info"],
            bg=UI_COLORS["card"]
        )
        self.result_label.grid(row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(2, 6))

        self.score_label = ttk.Label(
            result_card,
            text="Static Risk: - | Dynamic Risk: -",
            style="Normal.TLabel"
        )
        self.score_label.grid(row=2, column=0, sticky="w", padx=16, pady=4)

        # Risk chart container
        self.risk_chart_frame = tk.Frame(
            result_card,
            bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            highlightbackground=UI_COLORS["border"],
            highlightthickness=1
        )
        self.risk_chart_frame.grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=16,
            pady=(6, 14)
        )

        result_card.rowconfigure(5, weight=0)

        self.runtime_label = ttk.Label(
            result_card,
            text="Runtime Evidence: -",
            style="Normal.TLabel"
        )
        self.runtime_label.grid(row=2, column=1, sticky="w", padx=16, pady=4)

        self.culpability_label = ttk.Label(
            result_card,
            text="Forensic Culpability: -",
            style="Normal.TLabel"
        )
        self.culpability_label.grid(row=3, column=0, sticky="w", padx=16, pady=(4, 14))

        self.job_label = ttk.Label(
            result_card,
            text="Job Folder: -",
            style="Muted.TLabel"
        )
        self.job_label.grid(row=3, column=1, sticky="w", padx=16, pady=(4, 14))
        
        self.same_sample_label = tk.Label(
            result_card,
            text="Same Sample Verification: N/A",
            font=("Segoe UI", 10, "bold"),
            fg=UI_COLORS["muted"],
            bg=UI_COLORS["card"]
        )
        self.same_sample_label.grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="w",
            padx=16,
            pady=(0, 12)
        )

        result_card.columnconfigure(0, weight=1)
        result_card.columnconfigure(1, weight=1)

        # Log card
        log_card = self.create_card(main)
        log_card.pack(fill="both", expand=True)

        ttk.Label(
            log_card,
            text="Execution Log",
            style="Section.TLabel"
        ).pack(anchor="w", padx=16, pady=(14, 8))

        self.log_box = scrolledtext.ScrolledText(
            log_card,
            wrap=tk.WORD,
            height=18,
            font=("Consolas", 10),
            bg=UI_COLORS["log_bg"],
            fg=UI_COLORS["log_fg"],
            insertbackground=UI_COLORS["primary"],
            selectbackground="#1e40af",
            selectforeground="#ffffff",
            relief="flat",
            padx=12,
            pady=12
        )
        self.log_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        
        self.toggle_cape_json_input()
        self.update_risk_chart()

    def update_risk_chart(self, static_risk=None, dynamic_risk=None):
        """
        Draws a compact static vs dynamic risk chart inside the app.
        """

        # Clear previous chart
        for widget in self.risk_chart_frame.winfo_children():
            widget.destroy()

        if static_risk is None or dynamic_risk is None:
            placeholder = tk.Label(
                self.risk_chart_frame,
                text="Risk chart will appear after analysis.",
                bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
                fg=UI_COLORS["muted"],
                font=("Segoe UI", 9)
            )
            placeholder.pack(anchor="w", padx=12, pady=10)
            return

        static_risk = float(static_risk)
        dynamic_risk = float(dynamic_risk)

        fig = Figure(figsize=(5.8, 1.45), dpi=100)
        fig.patch.set_facecolor(UI_COLORS.get("card_alt", UI_COLORS["card"]))

        ax = fig.add_subplot(111)
        ax.set_facecolor(UI_COLORS.get("card_alt", UI_COLORS["card"]))

        labels = ["Static Risk", "Dynamic Risk"]
        values = [static_risk, dynamic_risk]

        colors = [
            UI_COLORS["warning"] if static_risk >= 0.5 else UI_COLORS["success"],
            UI_COLORS["danger"] if dynamic_risk >= 0.5 else UI_COLORS["info"]
        ]

        bars = ax.barh(labels, values, color=colors, height=0.42)

        ax.set_xlim(0, 1)
        ax.set_xlabel("Malicious Probability", color=UI_COLORS["muted"], fontsize=8)

        ax.tick_params(axis="x", colors=UI_COLORS["muted"], labelsize=8)
        ax.tick_params(axis="y", colors=UI_COLORS["text"], labelsize=9)

        ax.grid(axis="x", linestyle="--", alpha=0.18, color=UI_COLORS["muted"])

        for spine in ax.spines.values():
            spine.set_visible(False)

        for bar, value in zip(bars, values):
            ax.text(
                min(value + 0.025, 0.93),
                bar.get_y() + bar.get_height() / 2,
                f"{value:.4f}",
                va="center",
                ha="left",
                fontsize=8,
                color=UI_COLORS["text"]
            )

        fig.tight_layout(pad=1.1)

        canvas = FigureCanvasTkAgg(fig, master=self.risk_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="x", padx=8, pady=6)

    def show_result_popup(
        self,
        static_result,
        label,
        prob,
        runtime,
        hybrid_result,
        incident_correlation,
        reported_incident_type,
        result
    ):
        popup = tk.Toplevel(self.root)
        popup.title("Prediction Result")
        self.set_app_icon(popup)
        try:
            popup.iconbitmap(resource_path("nexforensic_ai_icon.ico"))
        except Exception:
            pass
        popup.geometry("700x700")
        popup.minsize(720, 560)
        popup.configure(bg=UI_COLORS["bg"])
        popup.transient(self.root)
        popup.grab_set()

        culpability = incident_correlation.get("culpability", {})

        # Center popup over main window
        popup.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 350
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 260
        popup.geometry(f"+{x}+{y}")

        container = tk.Frame(
            popup,
            bg=UI_COLORS["card"],
            highlightbackground=UI_COLORS["border"],
            highlightthickness=1
        )
        container.pack(fill="both", expand=True, padx=18, pady=18)

        # Header
        header = tk.Frame(container, bg=UI_COLORS["card"])
        header.pack(fill="x", padx=18, pady=(18, 10))

        title = tk.Label(
            header,
            text="Prediction Result",
            font=("Segoe UI", 18, "bold"),
            fg=UI_COLORS["primary"],
            bg=UI_COLORS["card"]
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text="Hybrid malware analysis and forensic correlation summary",
            font=("Segoe UI", 9),
            fg=UI_COLORS["muted"],
            bg=UI_COLORS["card"]
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        # Verdict card
        verdict_color = self.map_verdict_color(hybrid_result.get("hybrid_color", "blue"))

        verdict_frame = tk.Frame(
            container,
            bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            highlightbackground=UI_COLORS["border"],
            highlightthickness=1
        )
        verdict_frame.pack(fill="x", padx=18, pady=(8, 12))

        tk.Label(
            verdict_frame,
            text="Final Hybrid Verdict",
            font=("Segoe UI", 10, "bold"),
            fg=UI_COLORS["muted"],
            bg=UI_COLORS.get("card_alt", UI_COLORS["card"])
        ).pack(anchor="w", padx=14, pady=(12, 2))

        tk.Label(
            verdict_frame,
            text=hybrid_result.get("hybrid_verdict", "-"),
            font=("Segoe UI", 15, "bold"),
            fg=verdict_color,
            bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            wraplength=640,
            justify="left"
        ).pack(anchor="w", padx=14, pady=(0, 12))

        # Content area
        body = tk.Frame(container, bg=UI_COLORS["card"])
        body.pack(fill="x", padx=18, pady=(0, 12))
        
        def section(parent, title_text, content_text, color=None):
            frame = tk.Frame(
                parent,
                bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
                highlightbackground=UI_COLORS["border"],
                highlightthickness=1
            )
            frame.pack(fill="x", pady=(0, 10))
        
            tk.Label(
                frame,
                text=title_text,
                font=("Segoe UI", 10, "bold"),
                fg=UI_COLORS["primary"],
                bg=UI_COLORS.get("card_alt", UI_COLORS["card"])
            ).pack(anchor="w", padx=12, pady=(10, 4))
        
            tk.Label(
                frame,
                text=content_text,
                font=("Segoe UI", 10),
                fg=color or UI_COLORS["text"],
                bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
                justify="left",
                wraplength=640
            ).pack(anchor="w", padx=12, pady=(0, 10))
        
        
        section(
            body,
            "Incident Context",
            f"Reported incident type: {reported_incident_type}"
        )
        
        analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")
        
        if analysis_mode == "CAPE JSON Dynamic Input":
            same_sample_status = result.get("same_sample_verification", "Unknown")
            section(
                body,
                "Same Sample Verification",
                (
                    f"Verification Status: {result.get('same_sample_verification', 'Unknown')}\n"
                    f"PDF SHA256: {result.get('pdf_sha256', '-')}\n"
                    f"CAPE JSON SHA256: {result.get('cape_sample_sha256', '-')}\n"
                    f"Note: {result.get('same_sample_reason', '-')}"
                ),
                color=(
                    UI_COLORS["success"]
                    if result.get("same_sample_verification") == "Matched"
                    else UI_COLORS["warning"]
                )
            )
        
        section(
            body,
            "Forensic Culpability",
            (
                f"{culpability.get('culpability', '-')}\n"
                f"Correlation Strength: {culpability.get('Correlation Strength', '-')}"
            )
        )

        explanation_frame = tk.Frame(
            container,
            bg=UI_COLORS.get("card_alt", UI_COLORS["card"]),
            highlightbackground=UI_COLORS["border"],
            highlightthickness=1
        )
        explanation_frame.pack(fill="x", padx=18, pady=(0, 12))

        report_path = result.get("forensic_report_pdf_path", "-")

        report_frame = tk.Frame(container, bg=UI_COLORS["card"])
        report_frame.pack(fill="x", padx=18, pady=(0, 14))

        tk.Label(
            report_frame,
            text=f"PDF Report: {report_path}",
            font=("Consolas", 8),
            fg=UI_COLORS["muted"],
            bg=UI_COLORS["card"],
            wraplength=650,
            justify="left"
        ).pack(anchor="w")

        # Buttons
        button_frame = tk.Frame(container, bg=UI_COLORS["card"])
        button_frame.pack(fill="x", padx=18, pady=(0, 18))

        ok_btn = tk.Button(
            button_frame,
            text="OK",
            command=popup.destroy,
            bg=UI_COLORS["button_bg"],
            fg=UI_COLORS["text"],
            activebackground=UI_COLORS["button_active"],
            activeforeground=UI_COLORS["text"],
            relief="flat",
            font=("Segoe UI", 10),
            padx=18,
            pady=8
        )
        ok_btn.pack(side="right")

    def map_verdict_color(self, color_name):
        color_map = {
            "red": UI_COLORS["danger"],
            "green": UI_COLORS["success"],
            "orange": UI_COLORS["warning"],
            "darkorange": UI_COLORS["warning"],
            "blue": UI_COLORS["info"],
        }

        return color_map.get(color_name, UI_COLORS["info"])


    def map_runtime_color(self, runtime_verdict):
        runtime_verdict = str(runtime_verdict)

        if "Strong Dynamic" in runtime_verdict:
            return UI_COLORS["danger"]

        if "Moderate" in runtime_verdict or "Weak" in runtime_verdict:
            return UI_COLORS["warning"]

        if "No Strong" in runtime_verdict:
            return UI_COLORS["muted"]

        return UI_COLORS["info"]

    def map_same_sample_color(self, status):
        status = str(status or "Unknown").strip()

        if status == "Matched":
            return UI_COLORS["success"]   # Green

        if status == "Not Matched":
            return UI_COLORS["danger"]    # Red

        return UI_COLORS["warning"]       # Yellow / Amber

    def create_card(self, parent):
        frame = tk.Frame(
            parent,
            bg=UI_COLORS["card"],
            highlightbackground=UI_COLORS["border"],
            highlightcolor=UI_COLORS["primary"],
            highlightthickness=1,
            bd=0
        )
        return frame

    def browse_pdf(self):
        file_path = filedialog.askopenfilename(
            title="Select PDF File",
            filetypes=[("PDF files", "*.pdf")]
        )
        if file_path:
            self.selected_pdf.set(file_path)

    def log(self, message):
        self.log_box.insert(tk.END, message)
        self.log_box.see(tk.END)
        self.root.update_idletasks()

    def clear_log(self):
        self.log_box.delete("1.0", tk.END)

    def open_pdf_report(self):
        if not self.last_pdf_report_path:
            messagebox.showwarning("No Report", "No PDF report is available yet.")
            return

        report_path = Path(self.last_pdf_report_path)

        if not report_path.exists():
            messagebox.showerror("Report Not Found", f"PDF report not found:\n{report_path}")
            return

        webbrowser.open(report_path.as_uri())

    def set_running(self, running=True):
        if running:
            self.run_btn.config(state="disabled", text="Running Analysis...")
        else:
            self.run_btn.config(state="normal", text="Run Analysis")

    def run_analysis_thread(self):
        pdf_path = self.selected_pdf.get().strip()
        if not pdf_path:
            messagebox.showwarning("Missing PDF", "Please select a PDF file first.")
            return

        self.set_running(True)

        self.result_label.config(
            text="Final Verdict: Running...",
            fg=UI_COLORS["info"]
        )
        self.score_label.config(text="Static Risk: - | Dynamic Risk: -")
        self.runtime_label.config(text="Runtime Evidence: -")
        self.culpability_label.config(text="Forensic Culpability: -")
        self.same_sample_label.config(
            text="Same Sample Verification: N/A",
            fg=UI_COLORS["muted"]
        )
        self.job_label.config(text="Job Folder: -")
        self.update_risk_chart()
        
        self.last_pdf_report_path = None
        self.open_pdf_report_btn.config(state="disabled")
        
        self.log("\n" + "=" * 70 + "\n")
        self.log(f"Starting analysis for:\n{pdf_path}\n\n")

        reported_incident_type = self.reported_incident_type.get()
        use_cape_json_dynamic = self.use_cape_json_dynamic.get()
        cape_json_path = self.selected_cape_json.get().strip()
        
        if use_cape_json_dynamic and not cape_json_path:
            messagebox.showerror(
                "Error",
                "CAPE JSON Dynamic Input is enabled. Please select a CAPEv2 JSON report."
            )
            return
        
        self.log(f"Selected incident type: {reported_incident_type}\n")
        self.log(f"CAPE JSON dynamic mode: {use_cape_json_dynamic}\n")

        if use_cape_json_dynamic:
            self.log(f"CAPE JSON report:\n{cape_json_path}\n\n")
            
        print("DEBUG use_cape_json_dynamic =", use_cape_json_dynamic)
        print("DEBUG cape_json_path =", cape_json_path)
        thread = threading.Thread(
            target=self.run_analysis,
            args=(pdf_path, reported_incident_type, use_cape_json_dynamic, cape_json_path),
            daemon=True
        )
        thread.start()

    def run_analysis(
        self,
        pdf_path,
        reported_incident_type,
        use_cape_json_dynamic=False,
        cape_json_path=None
    ):
        try:
            result = predict_pdf(
                pdf_path,
                self.log,
                reported_incident_type=reported_incident_type,
                use_cape_json_dynamic=use_cape_json_dynamic,
                cape_json_path=cape_json_path
            )

            label = result["prediction_label"]
            prob = result["malicious_probability"]
            job_dir = result["job_dir"]

            runtime = result["runtime_evidence"]
            runtime_verdict = runtime["runtime_verdict"]
            
            static_result = result["static_result"]
            hybrid_result = result["hybrid_result"]
            incident_correlation = result.get("incident_correlation", {})
            culpability = incident_correlation.get("culpability", {})
            
            final_text = f"Final Hybrid Verdict: {hybrid_result['hybrid_verdict']}"
            color_map = {
                "red": UI_COLORS["danger"],
                "green": UI_COLORS["success"],
                "orange": UI_COLORS["warning"],
                "darkorange": UI_COLORS["warning"],
                "blue": UI_COLORS["info"],
            }

            final_color = color_map.get(
                hybrid_result.get("hybrid_color", "blue"),
                UI_COLORS["info"]
            )

            self.result_label.config(text=final_text, fg=final_color)

            self.score_label.config(
                text=(
                    f"Static Risk: {static_result['static_probability']:.4f} | "
                    f"Dynamic Risk: {prob:.4f}"
                )
            )

            self.update_risk_chart(
                static_risk=static_result["static_probability"],
                dynamic_risk=prob
            )

            self.job_label.config(text=f"Job Folder: {job_dir}")
            self.runtime_label.config(
                text=f"Runtime Evidence: {runtime.get('runtime_verdict', '-')}"
            )

            self.culpability_label.config(
                text=(
                    "Forensic Culpability: "
                    f"{culpability.get('culpability', '-')}"
                )
            )

            analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")

            if analysis_mode == "CAPE JSON Dynamic Input":
                same_sample_status = result.get("same_sample_verification", "Unknown")

                self.same_sample_label.config(
                    text=f"Same Sample Verification: {same_sample_status}",
                    fg=self.map_same_sample_color(same_sample_status)
                )
            else:
                self.same_sample_label.config(
                    text="Same Sample Verification: N/A",
                    fg=UI_COLORS["muted"]
                )

            self.last_pdf_report_path = result.get("forensic_report_pdf_path")
            self.last_html_report_path = result.get("forensic_report_html_path")

            if self.last_pdf_report_path:
                self.open_pdf_report_btn.config(state="normal")

            if self.last_pdf_report_path:
                self.open_pdf_report_btn.config(state="normal")
            
            analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")

            self.log("\n=== FINAL RESULT ===\n")
            self.log(f"Analysis mode: {analysis_mode}\n")
            self.log(f"Reported incident type: {reported_incident_type}\n")
            self.log(f"Static prediction: {static_result['static_label']}\n")
            self.log(f"Static malicious probability: {static_result['static_probability']:.4f}\n")
            self.log("\n=== STATIC SHAP EXPLANATION ===\n")
            self.log(static_result["static_shap"]["explanation_text"] + "\n")
            self.log(f"Dynamic RF prediction: {label}\n")
            self.log(f"Dynamic malicious probability: {prob:.4f}\n")
            self.log("\n=== DYNAMIC SHAP EXPLANATION ===\n")
            self.log(result["dynamic_shap"]["explanation_text"] + "\n")
            self.log(f"Hybrid verdict: {hybrid_result['hybrid_verdict']}\n")
            self.log(f"Hybrid explanation: {hybrid_result['hybrid_explanation']}\n")
            self.log(f"Job folder: {job_dir}\n")
            self.log(f"Forensic report: {result.get('forensic_report_pdf_path', '-')}\n")
            runtime = result["runtime_evidence"]

            self.log("\n=== RUNTIME EVIDENCE VERDICT ===\n")
            self.log(f"Runtime verdict: {runtime['runtime_verdict']}\n")
            self.log(f"Explanation: {runtime['runtime_explanation']}\n")

            if runtime["core_hits"]:
                self.log("Core hits:\n")
                for item in runtime["core_hits"]:
                    self.log(f"  - {item}\n")

            if runtime["supporting_hits"] and runtime["runtime_verdict"] != "No Strong Runtime Evidence":
                self.log("Supporting hits:\n")
                for item in runtime["supporting_hits"]:
                    self.log(f"  - {item}\n")
            
            if result["saved_artifacts_dir"]:
                self.log(f"\nCopied artifacts to: {result['saved_artifacts_dir']}\n")

            self.log("\n=== IMPORTANT DYNAMIC FEATURES ===\n")
            for k, v in result["important_features"].items():
                self.log(f"{k}: {v}\n")

            self.log("\n=== Model 2: Forensic Incident Correlation ===\n")
            self.log(incident_correlation["summary"] + "\n")

            self.log("\n=== FORENSIC REPORT SAVED ===\n")
            self.log(f"PDF report:\n{result.get('forensic_report_pdf_path', '-')}\n")
            self.log(f"HTML report:\n{result.get('forensic_report_html_path', '-')}\n")
            self.log(f"Static SHAP plot:\n{result.get('static_shap_plot_path', '-')}\n")
            self.log(f"Dynamic SHAP plot:\n{result.get('dynamic_shap_plot_path', '-')}\n")

            runtime = result["runtime_evidence"]

            self.show_result_popup(
                static_result=static_result,
                label=label,
                prob=prob,
                runtime=runtime,
                hybrid_result=hybrid_result,
                incident_correlation=incident_correlation,
                reported_incident_type=reported_incident_type,
                result=result
            )

        except Exception as e:
            self.result_label.config(text="Result: Error")
            self.score_label.config(text="Risk Score: -")
            self.job_label.config(text="Job Folder: -")
            self.log("\n=== ERROR ===\n")
            self.log(str(e) + "\n")
            messagebox.showerror("Error", str(e))

        finally:
            self.set_running(False)


if __name__ == "__main__":
    root = tk.Tk()
    app = DynamicTestApp(root)
    root.mainloop()