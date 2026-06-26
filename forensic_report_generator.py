# forensic_report_generator.py
# =========================================================
# Automated Forensic Report Generator
# =========================================================
# This module generates a human-readable forensic report
# from the output of Model 1 and Model 2.
#
# It does not run prediction.
# It only formats and explains the already-generated results.
# =========================================================

from datetime import datetime
from pathlib import Path
from matplotlib import lines
import matplotlib.pyplot as plt
import numpy as np
import os
import sys
import platform
import hashlib
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    Preformatted,
    Table,
    TableStyle,
)
import textwrap
import shutil

def resource_path(relative_path):
    """
    Gets the correct resource path when running as a script
    or as a PyInstaller executable.
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def safe_get(dictionary, key, default="-"):
    if isinstance(dictionary, dict):
        return dictionary.get(key, default)
    return default


def format_probability(value):
    try:
        return f"{float(value):.4f}"
    except Exception:
        return "-"


def format_feature_table(features_dict, max_items=None):
    if not isinstance(features_dict, dict) or not features_dict:
        return "No features available."

    items = list(features_dict.items())

    if max_items is not None:
        items = items[:max_items]

    lines = []
    for key, value in items:
        lines.append(f"- {key}: {value}")

    return "\n".join(lines)


def format_shap_section(shap_result, title):
    """
    Formats SHAP explanation section.
    """

    lines = []
    lines.append(title)
    lines.append("-" * len(title))

    if not isinstance(shap_result, dict):
        lines.append("No SHAP explanation available.")
        return "\n".join(lines)

    top_features = shap_result.get("top_features", [])

    if not top_features:
        explanation_text = shap_result.get("explanation_text", "")
        if explanation_text:
            lines.append(explanation_text)
        else:
            lines.append("No SHAP explanation available.")
        return "\n".join(lines)

    for item in top_features:
        feature = item.get("feature", "-")
        value = item.get("value", "-")
        shap_value = item.get("shap_value", 0)
        direction = item.get("direction", "-")

        try:
            shap_value = float(shap_value)
            shap_text = f"{shap_value:.4f}"
        except Exception:
            shap_text = str(shap_value)

        lines.append(
            f"- {feature} = {value} | SHAP: {shap_text} | Pushes toward: {direction}"
        )

    return "\n".join(lines)


def format_incident_correlation(incident_correlation):
    """
    Formats Model 2 forensic incident correlation output.
    """

    lines = []
    
    if not isinstance(incident_correlation, dict):
        lines.append("No incident correlation results available.")
        return "\n".join(lines)

    reported_incident_type = incident_correlation.get("reported_incident_type", "unknown")
    culpability = incident_correlation.get("culpability", {})
    incident_matches = incident_correlation.get("incident_matches", [])
    static_triggers = incident_correlation.get("static_triggers", [])
    
    analysis_mode = incident_correlation.get("analysis_mode", "-")
    same_sample_verification = incident_correlation.get("same_sample_verification", "Unknown")
    
    culpability_verdict = safe_get(culpability, "culpability")
    culpability_reasoning = safe_get(culpability, "explanation")
    
    if analysis_mode == "CAPE JSON Dynamic Input" and same_sample_verification != "Matched":
        if str(culpability_verdict).startswith("Culpable"):
            culpability_verdict = "Behaviorally Correlated / External Dynamic Evidence"
            culpability_reasoning = (
                "The selected PDF static result was combined with dynamic behavior extracted "
                "from the provided CAPEv2 JSON report. The dynamic evidence is behaviorally "
                "malicious, but same-sample causality is not confirmed because the PDF and "
                "CAPE sample hashes were not verified as matching."
            )
    
    lines.append(f"Reported Incident Type: {reported_incident_type}")
    lines.append(f"Culpability Verdict: {culpability_verdict}")
    lines.append(f"Correlation Strength: {safe_get(culpability, 'Correlation Strength')}")
    lines.append(f"Reasoning: {culpability_reasoning}")
    lines.append("")

    lines.append("Static Indicators:")
    if static_triggers:
        for item in static_triggers:
            lines.append(f"- {safe_get(item, 'feature')} = {safe_get(item, 'value')}")
    else:
        lines.append("- None detected")
    lines.append("")

    if str(reported_incident_type).lower() == "unknown":
        lines.append("Potential Attack / Behavior Categories:")
    else:
        lines.append("Matched Incident Categories:")

    if incident_matches:
        for match in incident_matches:
            lines.append(
                f"- {match.get('display_name', match.get('incident_id', '-'))} "
                f"| Correlation Strength: {match.get('Correlation Strength', '-')} "
                f"| Score: {match.get('score', '-')}/{match.get('max_score', '-')}"
            )

            for evidence in match.get("matched_evidence", []):
                lines.append(
                    f"  * {evidence.get('feature', '-')} = {evidence.get('value', '-')} "
                    f"(threshold: {evidence.get('threshold', '-')}, "
                    f"weight: {evidence.get('weight', '-')})"
                )
    else:
        summary = incident_correlation.get("summary", "")
        if "Suppressed:" in summary:
            lines.append(
                f"- Suppressed for reported incident type '{reported_incident_type}' "
                "because no confirmed runtime causality was observed."
            )
        else:
            lines.append("- None")

    return "\n".join(lines)

def save_shap_bar_plot(shap_result, output_path, title="SHAP Feature Impact", top_n=8):
    """
    Create a clean SHAP lollipop-style plot.

    Expects shap_result as a dict like:
    {
        "top_features": [...]
    }

    Positive SHAP -> pushes toward Malicious
    Negative SHAP -> pushes toward Benign
    """

    if not isinstance(shap_result, dict):
        return None

    shap_items = shap_result.get("top_features", [])
    if not shap_items:
        return None

    # Keep strongest top_n by absolute SHAP value
    shap_items = sorted(
        shap_items,
        key=lambda x: abs(float(x.get("shap_value", 0))),
        reverse=True
    )[:top_n]

    # Sort visually from most negative to most positive
    shap_items = sorted(
        shap_items,
        key=lambda x: float(x.get("shap_value", 0))
    )

    feature_labels = [str(item.get("feature", "unknown")) for item in shap_items]
    shap_values = [float(item.get("shap_value", 0)) for item in shap_items]

    y = np.arange(len(feature_labels))

    colors = ["#d9534f" if v > 0 else "#5bc0de" for v in shap_values]

    max_abs = max(abs(v) for v in shap_values) if shap_values else 1
    padding = max_abs * 0.18
    left_limit = min(shap_values) - padding
    right_limit = max(shap_values) + padding

    plt.figure(figsize=(8.2, 4.8 + len(feature_labels) * 0.28))
    ax = plt.gca()

    ax.set_facecolor("#fcfcfc")
    ax.axvline(0, color="#444444", linewidth=1.2, linestyle="-", alpha=0.85)

    for yi, val, color in zip(y, shap_values, colors):
        ax.hlines(y=yi, xmin=0, xmax=val, color=color, linewidth=2.6, alpha=0.95)
        ax.scatter(val, yi, s=85, color=color, edgecolor="white", linewidth=1.0, zorder=3)

        if val >= 0:
            ax.text(
                val + max_abs * 0.04,
                yi,
                f"{val:.3f}",
                va="center",
                ha="left",
                fontsize=9,
                color="#333333"
            )
        else:
            ax.text(
                val - max_abs * 0.04,
                yi,
                f"{val:.3f}",
                va="center",
                ha="right",
                fontsize=9,
                color="#333333"
            )

    ax.set_yticks(y)
    ax.set_yticklabels(feature_labels, fontsize=9)
    ax.set_xlabel("SHAP Value", fontsize=10)
    ax.set_ylabel("Feature", fontsize=10)
    ax.set_title(title, fontsize=13, weight="bold", pad=10)

    ax.set_xlim(left_limit, right_limit)

    ax.grid(axis="x", linestyle="--", alpha=0.25)
    ax.grid(axis="y", visible=False)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    plt.subplots_adjust(left=0.34, right=0.93)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.savefig(output_path, dpi=140, bbox_inches="tight")
    plt.close()

    return str(output_path)

def calculate_file_hashes(file_path):
    """
    Calculates MD5, SHA1, and SHA256 hashes for forensic evidence integrity.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        return {
            "md5": "-",
            "sha1": "-",
            "sha256": "-",
            "file_size_bytes": "-",
            "file_size_kb": "-",
            "file_name": file_path.name,
            "file_path": str(file_path),
            "exists": False
        }

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    file_size = file_path.stat().st_size

    return {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "file_size_bytes": file_size,
        "file_size_kb": round(file_size / 1024, 2),
        "file_name": file_path.name,
        "file_path": str(file_path),
        "exists": True
    }


def collect_analysis_environment(observe_seconds=None):
    """
    Collects controlled analysis environment metadata.
    """

    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "sandbox_guest_os": "Windows 10 VM",
        "pdf_execution_environment": "Guest VM / controlled sandbox",
        "observation_window_seconds": observe_seconds if observe_seconds is not None else "-",
        "analysis_mode": "Host-controlled offline VM-assisted dynamic analysis",
        "monitoring_tools": "Sysmon, Procmon",
        "pdf_reader": "Adobe Reader",
        "execution_note": "The PDF was executed inside the guest VM. The host application generated the report and preserved the original evidence file."
    }


def collect_model_metadata():
    """
    Describes the models and reasoning layers used in the prototype.
    """

    return {
        "static_model": "LightGBM Static PDF Classifier",
        "static_model_file": "lgbm_static_model_v2.pkl",
        "dynamic_model": "Random Forest Dynamic Behavioral Classifier",
        "dynamic_model_file": "rf_dynamic_model.pkl",
        "static_xai": "SHAP TreeExplainer",
        "dynamic_xai": "SHAP TreeExplainer",
        "hybrid_layer": "Rule-based hybrid arbitration layer",
        "correlation_layer": "Rule-based forensic incident correlation engine",
        "reporting_layer": "Automated PDF/HTML forensic intelligence report generator",
        "current_status": "Prototype forensic decision-support system"
    }


def format_key_value_section(title, data):
    """
    Formats a dictionary as a clean report section.
    """

    lines = []
    lines.append(title)
    lines.append("-" * len(title))
    
    if not isinstance(data, dict) or not data:
        lines.append("- No data available.")
        return "\n".join(lines)

    for key, value in data.items():
        pretty_key = str(key).replace("_", " ").title()
        lines.append(f"{pretty_key}: {value}")

    return "\n".join(lines)


def list_generated_artifacts(result):
    """
    Lists generated artifacts from the job folder and report output.
    Handles Live VM mode and CAPE JSON mode differently.
    """

    lines = []

    analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")
    job_dir = result.get("job_dir", "-")

    lines.append(f"Job Folder: {job_dir}")

    artifact_keys = {
        "Forensic Text Report": "forensic_report_path",
        "Forensic HTML Report": "forensic_report_html_path",
        "Forensic PDF Report": "forensic_report_pdf_path",
        "Static SHAP Plot": "static_shap_plot_path",
        "Dynamic SHAP Plot": "dynamic_shap_plot_path",
        "Saved Artifacts Copy": "saved_artifacts_dir",
    }

    for label, key in artifact_keys.items():
        value = result.get(key)
        if value:
            lines.append(f"{label}: {value}")

    lines.append("")

    if analysis_mode == "CAPE JSON Dynamic Input":
        lines.append("Live VM Job Files:")
        lines.append("- Not applicable in CAPE JSON Dynamic Input mode.")
        lines.append("- The VM was skipped during this run.")
        lines.append("- Dynamic evidence source: selected CAPEv2 JSON report.")

        cape_json_path = result.get("cape_json_path")
        if cape_json_path:
            lines.append(f"- CAPE JSON Report: {cape_json_path}")

        same_sample_status = result.get("same_sample_verification")
        if same_sample_status:
            lines.append(f"- Same Sample Verification: {same_sample_status}")

        return "\n".join(lines)

    if job_dir != "-":
        job_path = Path(job_dir)
        expected_files = [
            "status.json",
            "procmon.csv",
            "sysmon.xml"
        ]

        lines.append("Expected Job Files:")
        for filename in expected_files:
            path = job_path / filename
            status = "Present" if path.exists() else "Not Found"
            lines.append(f"- {filename}: {status}")

    return "\n".join(lines)


def build_confidence_interpretation(result):
    """
    Explains how to interpret confidence and culpability.
    """

    incident_correlation = result.get("incident_correlation", {})
    culpability = incident_correlation.get("culpability", {})

    Correlation_Strength = str(culpability.get("Correlation Strength", "-"))
    culpability_label = str(culpability.get("culpability", "-"))

    analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")
    same_sample_verification = result.get("same_sample_verification", "Unknown")

    if analysis_mode == "CAPE JSON Dynamic Input" and same_sample_verification != "Matched":
        if culpability_label.startswith("Culpable"):
            culpability_label = "Behaviorally Correlated / External Dynamic Evidence"

    lines = []
    lines.append(f"Culpability Verdict: {culpability_label}")
    lines.append(f"Correlation Strength: {Correlation_Strength}")
    lines.append("")

    if Correlation_Strength.lower() == "high":
        lines.append(
            "Interpretation: The available static and runtime evidence strongly supports "
            "a correlation between the analyzed PDF and the reported incident category."
        )
    elif Correlation_Strength.lower() == "medium":
        lines.append(
            "Interpretation: The evidence suggests possible correlation, but additional "
            "analyst validation or independent organizational logs are required before "
            "assigning definitive incident causality."
        )
    elif Correlation_Strength.lower() == "low":
        lines.append(
            "Interpretation: The available evidence is insufficient to establish incident "
            "causality. The file may still be suspicious, but it is not strongly linked to "
            "the selected incident type."
        )
    else:
        lines.append(
            "Interpretation: Correlation strength could not be determined automatically."
        )

    return "\n".join(lines)


def build_chain_of_custody_section(evidence_info, analyst_name, result):
    """
    Creates a lightweight chain-of-custody style section.
    """

    lines = []
    lines.append(f"Evidence Identifier: {evidence_info.get('sha256', '-')}")
    lines.append(f"Original File Name: {evidence_info.get('file_name', '-')}")
    lines.append(f"Original Evidence Path: {evidence_info.get('file_path', '-')}")
    lines.append(f"Analysis Performed By: {analyst_name}")
    lines.append(f"Analysis Output Folder: {result.get('job_dir', '-')}")
    lines.append("Evidence Handling Statement: The original evidence file was read for analysis and hashing. The generated reports and artifacts were stored separately in the job output folder.")
    lines.append("Custody Status: Automated analysis record generated; final human analyst validation is required.")
    return "\n".join(lines)


def build_analyst_review_section():
    """
    Adds a final human review / sign-off section.
    """

    return """Review Status: Pending human analyst validation

Analyst Name: _______________________________

Analyst Role / Department: __________________

Review Decision:
[ ] Accepted
[ ] Accepted with limitations
[ ] Requires further analysis
[ ] Rejected

Analyst Notes:
____________________________________________________________
____________________________________________________________
____________________________________________________________

Signature: ________________________

Date: _____________________________"""

def generate_forensic_report(
    result,
    pdf_path=None,
    analyst_name="Automated Analysis",
    observe_seconds=None
):
    """
    Generates a complete forensic report as plain text.

    Parameters:
        result: dict
            The full result returned by predict_pdf().

        pdf_path: str optional
            Original analyzed PDF path.

        analyst_name: str
            Name shown in report.

    Returns:
        str
            Complete formatted forensic report.
    """

    if not isinstance(result, dict):
        raise ValueError("Result must be a dictionary.")

    static_result = result.get("static_result", {})
    hybrid_result = result.get("hybrid_result", {})
    runtime_evidence = result.get("runtime_evidence", {})
    important_features = result.get("important_features", {})
    incident_correlation = result.get("incident_correlation", {})
    dynamic_shap = result.get("dynamic_shap", {})

    static_shap = {}
    if isinstance(static_result, dict):
        static_shap = static_result.get("static_shap", {})

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    evidence_info = calculate_file_hashes(pdf_path) if pdf_path else {}
    environment_info = collect_analysis_environment(observe_seconds=observe_seconds)
    model_metadata = collect_model_metadata()

    analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")

    if isinstance(incident_correlation, dict):
        incident_correlation = dict(incident_correlation)
        incident_correlation["analysis_mode"] = analysis_mode
        incident_correlation["same_sample_verification"] = result.get(
            "same_sample_verification",
            "Unknown"
        )

    if analysis_mode == "CAPE JSON Dynamic Input":
        # Remove VM-specific fields because the VM was not used in this mode.
        for key in [
            "sandbox_guest_os",
            "pdf_execution_environment",
            "observation_window_seconds",
            "monitoring_tools",
            "pdf_reader",
        ]:
            environment_info.pop(key, None)
    
        environment_info["analysis_mode"] = "CAPE JSON Dynamic Input"
        environment_info["dynamic_source"] = "Selected CAPEv2 JSON report"
        environment_info["vm_execution"] = "Skipped"
        environment_info["cape_json_report"] = result.get("cape_json_path", "-")
        environment_info["pdf_sha256"] = result.get("pdf_sha256", evidence_info.get("sha256", "-"))
        environment_info["cape_sample_sha256"] = result.get("cape_sample_sha256", "-")
        environment_info["same_sample_verification"] = result.get("same_sample_verification", "Unknown")
        environment_info["execution_note"] = (
            "Dynamic behavior was extracted from a provided CAPEv2 JSON report. "
            "The selected PDF was not executed in the local VM during this run."
        )
    elif analysis_mode == "Dataset Dynamic Replay":
        environment_info["analysis_mode"] = "Dataset Dynamic Replay"
        environment_info["dynamic_source"] = "Pre-extracted CAPEv2 behavioral feature row"
        environment_info["vm_execution"] = "Skipped"
    else:
        environment_info["analysis_mode"] = "Live VM Dynamic Analysis"
        environment_info["dynamic_source"] = "Live VM execution using Sysmon and Procmon"
        environment_info["vm_execution"] = "Enabled"

    lines = []
    lines.append("")
    lines.append("=" * 72)
    lines.append("AUTOMATED PDF MALWARE FORENSIC INTELLIGENCE REPORT")
    lines.append("=" * 72)
    lines.append("")

    # =====================================================
    # 1. Case Information
    # =====================================================
    lines.append("1. Case Information")
    lines.append("-------------------")
    lines.append(f"Report Generated At: {report_time}")
    lines.append(f"Analyst / System: {analyst_name}")
    lines.append(f"Analyzed PDF: {pdf_path if pdf_path else '-'}")
    lines.append(f"Job Folder: {result.get('job_dir', '-')}")
    lines.append(f"Report Type: Automated PDF Malware Forensic Intelligence Report")
    lines.append(f"Report Status: Prototype forensic decision-support output")
    lines.append("")
    
    lines.append("2. Evidence Integrity")
    lines.append("---------------------")
    lines.append(f"Original File Name: {evidence_info.get('file_name', '-')}")
    lines.append(f"Original File Path: {evidence_info.get('file_path', '-')}")
    lines.append(f"File Exists During Analysis: {evidence_info.get('exists', '-')}")
    lines.append(f"File Size: {evidence_info.get('file_size_bytes', '-')} bytes ({evidence_info.get('file_size_kb', '-')} KB)")
    lines.append(f"MD5: {evidence_info.get('md5', '-')}")
    lines.append(f"SHA1: {evidence_info.get('sha1', '-')}")
    lines.append(f"SHA256: {evidence_info.get('sha256', '-')}")
    lines.append("Integrity Statement: The original evidence file was hashed before report generation and was not intentionally modified by the reporting module.")
    lines.append("")
    
    lines.append("3. Chain of Custody and Traceability")
    lines.append("------------------------------------")
    lines.append(build_chain_of_custody_section(evidence_info, analyst_name, result))
    lines.append("")
    
    lines.append("4. Analysis Environment")
    lines.append("-----------------------")
    lines.append(format_key_value_section("Environment Metadata", environment_info))
    lines.append("")
    
    lines.append("5. Model and Tool Versioning")
    lines.append("----------------------------")
    lines.append(format_key_value_section("Model Metadata", model_metadata))
    lines.append("")

    # =====================================================
    # 2. Executive Summary
    # =====================================================
    lines.append("6. Executive Summary")
    lines.append("--------------------")
    lines.append(f"Analysis Mode: {analysis_mode}")
    lines.append(f"Static Verdict: {safe_get(static_result, 'static_label')}")
    lines.append(
        f"Static Malicious Probability: "
        f"{format_probability(safe_get(static_result, 'static_probability'))}"
    )
    lines.append(f"Dynamic Verdict: {result.get('prediction_label', '-')}")
    lines.append(
        f"Dynamic Malicious Probability: "
        f"{format_probability(result.get('malicious_probability', '-'))}"
    )
    lines.append(
        f"Behavioral Runtime Verdict: "
        f"{safe_get(runtime_evidence, 'runtime_verdict')}"
    )
    lines.append(f"Runtime Evidence Verdict: {safe_get(runtime_evidence, 'runtime_verdict')}")
    lines.append(f"Final Hybrid Verdict: {safe_get(hybrid_result, 'hybrid_verdict')}")
    lines.append(f"Hybrid Explanation: {safe_get(hybrid_result, 'hybrid_explanation')}")

    if analysis_mode == "CAPE JSON Dynamic Input":
        same_sample_status = result.get("same_sample_verification", "Unknown")
        pdf_sha256 = result.get("pdf_sha256", "-")
        cape_sample_sha256 = result.get("cape_sample_sha256", "-")
        same_sample_reason = result.get("same_sample_reason", "-")

        lines.append("")
        lines.append("External Dynamic Evidence Verification:")
        lines.append(f"- Same Sample Verification: {same_sample_status}")
        lines.append(f"- PDF SHA256: {pdf_sha256}")
        lines.append(f"- CAPE JSON SHA256: {cape_sample_sha256}")

        if same_sample_status == "Matched":
            lines.append(
                "- Interpretation: The selected PDF and CAPE JSON report appear to refer to the same sample. "
                "The external dynamic behavior can be treated as same-sample behavioral evidence, subject to analyst validation."
            )
        elif same_sample_status == "Not Matched":
            lines.append(
                "- Interpretation: The selected PDF and CAPE JSON report do not refer to the same sample. "
                "The dynamic behavior must be treated as external behavioral evidence, not direct runtime proof for the selected PDF."
            )
        else:
            lines.append(
                "- Interpretation: Same-sample verification could not be confirmed because the CAPE JSON SHA256 was unavailable or unreadable."
            )

        lines.append(f"- Verification Note: {same_sample_reason}")

    lines.append("")

    # =====================================================
    # 3. Static Analysis
    # =====================================================
    lines.append("7. Static Analysis Results")
    lines.append("--------------------------")
    lines.append(f"Static Prediction: {safe_get(static_result, 'static_label')}")
    lines.append(
        f"Static Malicious Probability: "
        f"{format_probability(safe_get(static_result, 'static_probability'))}"
    )
    lines.append("")
    lines.append(format_shap_section(static_shap, "Static SHAP Explanation"))
    lines.append("")

    # =====================================================
    # 4. Dynamic Analysis
    # =====================================================
    lines.append("8. Dynamic Analysis Results")
    lines.append("---------------------------")
    lines.append(f"Dynamic Prediction: {result.get('prediction_label', '-')}")
    lines.append(
        f"Dynamic Malicious Probability: "
        f"{format_probability(result.get('malicious_probability', '-'))}"
    )
    lines.append("")
    lines.append(format_shap_section(dynamic_shap, "Dynamic SHAP Explanation"))
    lines.append("")

    # =====================================================
    # 5. Runtime Evidence
    # =====================================================
    lines.append("9. Runtime Evidence Interpretation")
    lines.append("----------------------------------")
    lines.append(f"Runtime Verdict: {safe_get(runtime_evidence, 'runtime_verdict')}")
    lines.append(f"Runtime Explanation: {safe_get(runtime_evidence, 'runtime_explanation')}")
    lines.append("")

    core_hits = runtime_evidence.get("core_hits", [])
    supporting_hits = runtime_evidence.get("supporting_hits", [])

    lines.append("Core Runtime Hits:")
    if core_hits:
        for item in core_hits:
            lines.append(f"- {item}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("Supporting Runtime Hits:")

    runtime_verdict_text = str(safe_get(runtime_evidence, "runtime_verdict", ""))

    if supporting_hits and runtime_verdict_text != "No Strong Runtime Evidence":
        for item in supporting_hits:
            lines.append(f"- {item}")
    elif supporting_hits and runtime_verdict_text == "No Strong Runtime Evidence":
        lines.append("- Suppressed because no strong runtime evidence was confirmed.")
    else:
        lines.append("- None")

    lines.append("")

    lines.append("Important Dynamic Features:")
    lines.append(format_feature_table(important_features))
    lines.append("")

    # =====================================================
    # 6. Model 2 Correlation
    # =====================================================
    lines.append("10. Forensic Incident Correlation")
    lines.append("--------------------------------")
    lines.append(format_incident_correlation(incident_correlation))
    lines.append("")


    lines.append("11. Correlation Strength Interpretation")
    lines.append("-----------------------------")
    lines.append(build_confidence_interpretation(result))
    lines.append("")
    
    lines.append("12. Generated Artifacts")
    lines.append("-----------------------")
    lines.append(list_generated_artifacts(result))
    lines.append("")

    # =====================================================
    # 7. Final Forensic Conclusion
    # =====================================================
    culpability = incident_correlation.get("culpability", {})

    lines.append("13. Final Forensic Conclusion")
    lines.append("----------------------------")
    lines.append(f"Hybrid Verdict: {safe_get(hybrid_result, 'hybrid_verdict')}")
    final_culpability_label = safe_get(culpability, "culpability")
    
    if analysis_mode == "CAPE JSON Dynamic Input":
        same_sample_status = result.get("same_sample_verification", "Unknown")
    
        if same_sample_status != "Matched" and str(final_culpability_label).startswith("Culpable"):
            final_culpability_label = "Behaviorally Correlated / External Dynamic Evidence"
    
    lines.append(f"Forensic Culpability: {final_culpability_label}")
    lines.append(f"Correlation Strength: {safe_get(culpability, 'Correlation Strength')}")
    lines.append("")

    lines.append("Conclusion:")
    lines.append(build_final_conclusion(result))
    lines.append("")

    # =====================================================
    # 8. Notes
    # =====================================================
    lines.append("14. Notes and Limitations")
    lines.append("------------------------")
    lines.append(
        "- This report is generated automatically based on static analysis, "
        "dynamic analysis, SHAP explanations, and forensic correlation rules."
    )
    lines.append(
        "- Static malicious indicators may suggest malicious intent even when no "
        "runtime behavior is observed."
    )
    lines.append(
        "- Absence of runtime behavior does not always prove that a file is benign; "
        "the payload may be dormant, evasive, environment-dependent, or non-triggered."
    )
    lines.append(
        "- Final forensic conclusions should be reviewed by a qualified analyst "
        "before being used in legal or organizational decisions."
    )
    if analysis_mode == "CAPE JSON Dynamic Input":
        lines.append(
            "- In CAPE JSON Dynamic Input mode, dynamic behavior is extracted from an "
            "external CAPEv2 report. Unless same-sample hash verification is confirmed, "
            "the dynamic evidence should be treated as external behavioral validation, "
            "not direct proof of runtime behavior by the selected PDF."
        )

    lines.append("")
    lines.append("15. Analyst Review and Sign-off")
    lines.append("--------------------------------")
    lines.append(build_analyst_review_section())
    lines.append("")

    lines.append("")
    lines.append("=" * 72)
    lines.append("END OF REPORT")
    lines.append("=" * 72)

    return "\n".join(lines)


def build_final_conclusion(result):
    """
    Generates a short final conclusion paragraph based on the main verdicts.
    """

    static_result = result.get("static_result", {})
    hybrid_result = result.get("hybrid_result", {})
    runtime_evidence = result.get("runtime_evidence", {})
    incident_correlation = result.get("incident_correlation", {})

    analysis_mode = result.get("analysis_mode", "Live VM Dynamic Analysis")

    if analysis_mode == "CAPE JSON Dynamic Input" and isinstance(incident_correlation, dict):
        incident_correlation = dict(incident_correlation)

        culpability_data = incident_correlation.get("culpability", {})
        if isinstance(culpability_data, dict):
            culpability_data = dict(culpability_data)

            current_culpability = str(culpability_data.get("culpability", ""))

            if current_culpability.startswith("Culpable"):
                culpability_data["culpability"] = (
                    "Behaviorally Correlated / External Dynamic Evidence"
                )

                culpability_data["explanation"] = (
                    "The selected PDF static result was combined with dynamic behavior "
                    "extracted from the provided CAPEv2 JSON report. The dynamic evidence "
                    "is behaviorally malicious, but same-sample causality requires hash "
                    "verification between the PDF and the CAPE report."
                )

            incident_correlation["culpability"] = culpability_data

    static_label = safe_get(static_result, "static_label", "")
    runtime_verdict = safe_get(runtime_evidence, "runtime_verdict", "")
    hybrid_verdict = safe_get(hybrid_result, "hybrid_verdict", "")
    culpability = incident_correlation.get("culpability", {})
    culpability_label = safe_get(culpability, "culpability", "")

    if analysis_mode == "CAPE JSON Dynamic Input":
        same_sample_status = result.get("same_sample_verification", "Unknown")

        if same_sample_status == "Matched":
            return (
                "The selected PDF was evaluated using static analysis, and the provided "
                "CAPEv2 JSON report appears to match the same sample hash. The dynamic "
                "behavior demonstrated malicious runtime indicators and may be used as "
                "same-sample behavioral evidence, subject to analyst validation."
            )

        if same_sample_status == "Not Matched":
            return (
                "The selected PDF was evaluated using static analysis, while dynamic behavior "
                "was extracted from a CAPEv2 JSON report belonging to a different sample hash. "
                "The CAPEv2 report demonstrated malicious runtime indicators, but this result "
                "should be interpreted as external behavioral validation rather than proof that "
                "the selected PDF produced the observed runtime behavior during this run."
            )

        return (
            "The selected PDF was evaluated using static analysis, while dynamic behavior was "
            "extracted from the provided CAPEv2 JSON report. The CAPEv2 dynamic evidence "
            "demonstrated malicious runtime indicators; however, because same-sample hash "
            "verification was not confirmed, this result should be interpreted as external "
            "behavioral validation rather than proof that the selected PDF produced the observed "
            "runtime behavior during this run."
        )

    if "Dormant Malicious" in hybrid_verdict:
        return (
            "The analyzed PDF contains strong static indicators of malicious intent, "
            "but the dynamic execution did not produce strong malicious runtime behavior. "
            "The file should be treated as potentially malicious, but there is not enough "
            "runtime evidence to confirm incident causality in the current environment."
        )

    if "Benign" in hybrid_verdict and "Not Correlated" in culpability_label:
        return (
            "The analyzed PDF was classified as benign by both static and dynamic analysis. "
            "No strong runtime malicious indicators were observed, and the file is not "
            "correlated with the reported incident."
        )

    if "Strong Dynamic Malicious Evidence" in runtime_verdict:
        return (
            "The analyzed PDF demonstrated strong runtime malicious indicators during live "
            "dynamic analysis. The behavioral evidence should be treated as high-priority "
            "and reviewed against the reported incident timeline and affected system artifacts."
        )

    if "Requires Analyst Review" in culpability_label:
        return (
            "The analyzed PDF contains suspicious indicators, but the available evidence "
            "is not sufficient to establish clear causality. Analyst review is required."
        )

    if static_label == "Malicious":
        return (
            "The analyzed PDF was classified as malicious by the static model. "
            "Further analyst review is recommended, especially if the file is associated "
            "with an organizational incident."
        )

    return (
        "No sufficient evidence was found to classify the file as responsible for the "
        "reported incident based on the current analysis."
    )


def save_forensic_report(report_text, output_dir, filename="forensic_report.txt"):
    """
    Saves the generated report to disk.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / filename

    with report_path.open("w", encoding="utf-8") as f:
        f.write(report_text)

    return str(report_path)

def save_forensic_report_html(
    report_text,
    output_dir,
    filename="forensic_report.html",
    static_plot_path=None,
    dynamic_plot_path=None
):
    """
    Saves the forensic report as a readable HTML file.
    SHAP plots are placed directly under their corresponding SHAP explanation sections.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / filename

    def escape_html(text):
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def make_plot_block(title, plot_path):
        if not plot_path:
            return ""

        plot_name = Path(plot_path).name

        return f"""
        <div class="plot-card">
            <div class="plot-title">{title}</div>
            <img src="{plot_name}" alt="{title}" class="plot-image">
        </div>
        """

    static_plot_block = make_plot_block(
        "Static SHAP Plot",
        static_plot_path
    )

    dynamic_plot_block = make_plot_block(
        "Dynamic SHAP Plot",
        dynamic_plot_path
    )

    # Split the plain-text report so plots appear in the correct locations.
    static_marker = "8. Dynamic Analysis Results"
    dynamic_marker = "9. Runtime Evidence Interpretation"

    if static_marker in report_text and dynamic_marker in report_text:
        before_dynamic = report_text.split(static_marker)[0]
        dynamic_and_after = static_marker + report_text.split(static_marker, 1)[1]

        dynamic_section = dynamic_and_after.split(dynamic_marker)[0]
        after_dynamic = dynamic_marker + dynamic_and_after.split(dynamic_marker, 1)[1]

        report_html = f"""
        <pre>{escape_html(before_dynamic)}</pre>
        {static_plot_block}

        <pre>{escape_html(dynamic_section)}</pre>
        {dynamic_plot_block}

        <pre>{escape_html(after_dynamic)}</pre>
        """
    else:
        # Fallback if the expected section titles change later.
        report_html = f"""
        <pre>{escape_html(report_text)}</pre>
        {static_plot_block}
        {dynamic_plot_block}
        """
    logo_src_path = Path(resource_path("nexforensic_ai_icon.png"))
    logo_dst_path = Path(output_dir) / "nexforensic_ai_icon.png"

    if logo_src_path.exists():
        try:
            shutil.copy2(logo_src_path, logo_dst_path)
            favicon_href = "nexforensic_ai_icon.png"
        except Exception:
            favicon_href = ""
    else:
        favicon_href = ""
    favicon_html = (
        f'<link rel="icon" type="image/png" href="{favicon_href}">\n'
        f'<link rel="shortcut icon" type="image/png" href="{favicon_href}">\n'
        if favicon_href else ""
    )
    header_logo_html = (
        f'<img src="{favicon_href}" alt="NexForensic AI Logo" '
        f'style="width:34px;height:34px;vertical-align:middle;margin-right:10px;">'
        if favicon_href else ""
    )
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NexForensic AI Report</title>
    {favicon_html}
    <style>
        body {{
            font-family: Consolas, Arial, sans-serif;
            background: #f4f1ec;
            color: #1f1f1f;
            margin: 0;
            padding: 28px;
        }}

        .container {{
            max-width: 1050px;
            margin: auto;
            background: #fffaf2;
            border: 1px solid #c7b99c;
            border-radius: 14px;
            padding: 26px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }}

        h1 {{
            margin-top: 0;
            color: #5a3e1b;
            border-bottom: 2px solid #b08a52;
            padding-bottom: 12px;
            font-size: 24px;
        }}

        pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 13.5px;
            line-height: 1.45;
            background: #fcf8f2;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #e0d2bc;
            margin: 16px 0;
        }}

        .plot-card {{
            background: #fffdf8;
            border: 1px solid #d8c7a7;
            border-radius: 12px;
            padding: 14px 16px 18px 16px;
            margin: 14px auto 20px auto;
            max-width: 760px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }}

        .plot-title {{
            font-size: 17px;
            font-weight: bold;
            color: #5a3e1b;
            margin-bottom: 10px;
            border-bottom: 1px solid #d8c7a7;
            padding-bottom: 7px;
        }}

        .plot-image {{
            display: block;
            width: 100%;
            max-width: 720px;
            margin: 0 auto;
            border: 1px solid #ccb792;
            border-radius: 9px;
            background: white;
            padding: 6px;
        }}

        .footer {{
            margin-top: 24px;
            font-size: 12px;
            color: #6f6250;
        }}

        .badge {{
            display: inline-block;
            background: #5a3e1b;
            color: #fffaf2;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            margin-bottom: 14px;
        }}

        .report-note {{
            background: #fff4d8;
            border-left: 5px solid #b08a52;
            padding: 12px 14px;
            border-radius: 8px;
            margin: 16px 0;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{header_logo_html}NexForensic AI - Automated PDF Malware Forensic Report</h1>
        <div class="badge">Forensic Decision-Support Report</div>
        <div class="report-note">
            This report is automatically generated and must be reviewed by a qualified analyst before institutional or legal use.
        </div>
        
        {report_html}

        <div class="footer">
            Generated by NexForensic AI.
        </div>
    </div>
</body>
</html>
"""

    with report_path.open("w", encoding="utf-8") as f:
        f.write(html)

    return str(report_path)

def wrap_report_text_for_pdf(text, width=120):
    """
    Wraps only very long report lines so they do not overflow outside PDF margins.
    Keeps normal forensic report formatting readable.
    """

    wrapped_lines = []

    for line in str(text).splitlines():
        raw_line = line.rstrip()

        if not raw_line:
            wrapped_lines.append("")
            continue

        stripped = raw_line.strip()

        # Keep separators unchanged
        if stripped and all(ch == "=" for ch in stripped):
            wrapped_lines.append(raw_line)
            continue

        if stripped and all(ch == "-" for ch in stripped):
            wrapped_lines.append(raw_line)
            continue

        if stripped and all(ch == "_" for ch in stripped):
            wrapped_lines.append(raw_line)
            continue

        # Keep hashes unchanged
        if stripped.startswith(("MD5:", "SHA1:", "SHA256:")):
            wrapped_lines.append(raw_line)
            continue

        # Keep most paths unchanged
        if ":\\" in stripped and len(stripped) <= 145:
            wrapped_lines.append(raw_line)
            continue

        # Do not wrap normal-length lines
        if len(raw_line) <= width:
            wrapped_lines.append(raw_line)
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        prefix = " " * indent

        # Slightly narrower width for bullets
        effective_width = 112 if stripped.startswith("- ") else width

        wrapped = textwrap.wrap(
            raw_line,
            width=effective_width,
            subsequent_indent=prefix + "  ",
            break_long_words=False,
            break_on_hyphens=False
        )

        wrapped_lines.extend(wrapped if wrapped else [raw_line])

    return "\n".join(wrapped_lines)

def save_forensic_report_pdf(
    report_text,
    output_dir,
    filename="forensic_report.pdf",
    static_plot_path=None,
    dynamic_plot_path=None
):
    """
    Saves the forensic report as a professional PDF file.
    SHAP plots are inserted under their corresponding explanation sections.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = output_dir / filename

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#5a3e1b"),
        spaceAfter=16,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#6f6250"),
        spaceAfter=14,
    )

    section_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#5a3e1b"),
        spaceBefore=12,
        spaceAfter=8,
    )

    note_style = ParagraphStyle(
        "Note",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        leftIndent=8,
        rightIndent=8,
        textColor=colors.HexColor("#3b3329"),
        backColor=colors.HexColor("#fff4d8"),
        borderColor=colors.HexColor("#b08a52"),
        borderWidth=0.7,
        borderPadding=8,
        spaceAfter=12,
    )

    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.4,
        leading=9.2,
        textColor=colors.HexColor("#000000"),
    )

    story = []

    story.append(Paragraph("NexForensic AI", title_style))
    story.append(Paragraph("Automated PDF Malware Forensic Intelligence Report", subtitle_style))

    story.append(Paragraph(
        "This report is automatically generated as a forensic decision-support output. "
        "It must be reviewed by a qualified analyst before institutional or legal use.",
        note_style
    ))

    def add_plot(title, plot_path):
        if not plot_path:
            return

        plot_path = Path(plot_path)

        if not plot_path.exists():
            return

        story.append(Spacer(1, 8))
        story.append(Paragraph(title, section_style))

        img = Image(str(plot_path))

        # Keep image readable but not too large
        max_width = 6.2 * inch
        max_height = 3.6 * inch

        ratio = min(max_width / img.imageWidth, max_height / img.imageHeight)
        img.drawWidth = img.imageWidth * ratio
        img.drawHeight = img.imageHeight * ratio

        story.append(img)
        story.append(Spacer(1, 10))

    def add_text_block(text):
        wrapped_text = wrap_report_text_for_pdf(text.strip(), width=120)
        story.append(Preformatted(wrapped_text, mono_style))
        story.append(Spacer(1, 8))

    # Insert plots under the correct sections
    static_marker = "8. Dynamic Analysis Results"
    dynamic_marker = "9. Runtime Evidence Interpretation"

    if static_marker in report_text and dynamic_marker in report_text:
        before_dynamic = report_text.split(static_marker)[0]
        dynamic_and_after = static_marker + report_text.split(static_marker, 1)[1]

        dynamic_section = dynamic_and_after.split(dynamic_marker)[0]
        after_dynamic = dynamic_marker + dynamic_and_after.split(dynamic_marker, 1)[1]

        add_text_block(before_dynamic)
        add_plot("Static SHAP Plot", static_plot_path)

        add_text_block(dynamic_section)
        add_plot("Dynamic SHAP Plot", dynamic_plot_path)

        add_text_block(after_dynamic)

    else:
        PAGE_BREAK_MARKER = "[[PAGE_BREAK]]"

        report_parts = str(report_text).split(PAGE_BREAK_MARKER)

        for index, part in enumerate(report_parts):
            clean_part = part.replace(PAGE_BREAK_MARKER, "").strip()

            if index > 0:
                story.append(PageBreak())

            if clean_part:
                add_text_block(clean_part)

    def add_page_number(canvas, doc):
        canvas.saveState()

        footer_y = 24
        left_x = 42

        logo_path = resource_path("nexforensic_ai_icon.png")

        # Draw logo beside "Generated by NexForensic AI"
        if os.path.exists(logo_path):
            try:
                canvas.drawImage(
                    logo_path,
                    left_x,
                    footer_y - 3,
                    width=12,
                    height=12,
                    preserveAspectRatio=True,
                    mask="auto"
                )
                text_x = left_x + 16
            except Exception:
                text_x = left_x
        else:
            text_x = left_x

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6f6250"))

        canvas.drawString(text_x, footer_y, "Generated by NexForensic AI")

        page_text = f"Page {doc.page}"
        canvas.drawRightString(A4[0] - 42, footer_y, page_text)

        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)

    return str(pdf_path)
