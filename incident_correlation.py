# incident_correlation.py
# =========================================================
# Model 2 - Forensic Incident Correlation Engine
# =========================================================
# هذا الملف مسؤول عن ربط نتائج التحليل الديناميكي/الستاتيك
# مع سيناريوهات الحوادث الجنائية الرقمية مثل:
# Data Breach, Ransomware, Persistence, Process Injection...
#
# ملاحظة:
# هذا الملف لا يغيّر ولا يعيد تدريب أي model.
# هو فقط inference / reasoning layer فوق نتائج Model 1.
# =========================================================


# =========================================================
# 1) Incident Rules
# =========================================================
# كل incident type يحتوي على features مرتبطة فيه.
# الوزن weight يحدد أهمية الـ feature في هذا النوع من الحوادث.
# threshold يحدد أقل قيمة تعتبر evidence.
# =========================================================

INCIDENT_RULES = {  
    "data_breach": {
        "display_name": "Data Breach / Possible Exfiltration",
        "description": (
            "This incident type indicates possible outbound communication, "
            "DNS resolution, or network activity that may support a data breach scenario."
        ),
        "evidence": {
            "tcp_conn": {"weight": 2, "threshold": 1},
            "udp_conn": {"weight": 1, "threshold": 1},
            "http_requests": {"weight": 3, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "domains_count": {"weight": 2, "threshold": 1},
            "api_category_network_count": {"weight": 2, "threshold": 1},
        },
    },

    "ransomware_activity": {
        "display_name": "Ransomware-like File System Activity",
        "description": (
            "This incident type indicates suspicious file system behavior, "
            "such as file creation, deletion, or modification patterns."
        ),
        "evidence": {
            "files_created": {"weight": 2, "threshold": 1},
            "files_deleted": {"weight": 3, "threshold": 1},
            "api_category_file_count": {"weight": 1, "threshold": 50},
        },
    },

    "persistence_activity": {
        "display_name": "Persistence / Registry Modification",
        "description": (
            "This incident type indicates possible attempts to modify registry keys "
            "or maintain persistence on the system."
        ),
        "evidence": {
            "registry_written": {"weight": 3, "threshold": 1},
            "registry_keys_touched": {"weight": 2, "threshold": 1},
            "api_category_registry_count": {"weight": 1, "threshold": 20},
        },
    },

    "process_injection": {
        "display_name": "Process Injection / Memory Manipulation",
        "description": (
            "This incident type indicates behavior commonly associated with process injection, "
            "memory allocation, DLL loading, or remote thread creation."
        ),
        "evidence": {
            "api_writeprocessmemory_count": {"weight": 5, "threshold": 1},
            "api_createremotethread_count": {"weight": 5, "threshold": 1},
            "api_virtualprotectex_count": {"weight": 4, "threshold": 1},
            "api_ntallocatevirtualmemory_count": {"weight": 4, "threshold": 1},
            "api_ldrloaddll_count": {"weight": 2, "threshold": 1},
            "has_temp_exe_execution": {"weight": 5, "threshold": 1},
        },
    },

    "suspicious_process_behavior": {
        "display_name": "Suspicious Process Execution",
        "description": (
            "This incident type indicates abnormal process-related activity, "
            "such as high process interaction or suspicious API usage."
        ),
        "evidence": {
            "process_count": {"weight": 1, "threshold": 3},
            "suspicious_api_calls": {"weight": 3, "threshold": 1},
            "api_category_process_count": {"weight": 1, "threshold": 100},
        },
    },
        "phishing": {
        "display_name": "Phishing / Social Engineering",
        "description": (
            "This category indicates behavior commonly associated with phishing PDFs, "
            "such as embedded URLs, forms, or network redirection attempts."
        ),
        "evidence": {
            "URI": {"weight": 3, "threshold": 1},
            "Acroform": {"weight": 2, "threshold": 1},
            "AcroForm": {"weight": 2, "threshold": 1},
            "http_requests": {"weight": 2, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "domains_count": {"weight": 2, "threshold": 1},
        },
    },

    "trojan_behavior": {
        "display_name": "Trojan Horse / Malicious Payload Behavior",
        "description": (
            "This category indicates behavior commonly associated with Trojan activity, "
            "such as suspicious process execution, payload dropping, registry modification, "
            "or outbound communication."
        ),
        "evidence": {
            "suspicious_api_calls": {"weight": 3, "threshold": 50},
            "process_count": {"weight": 1, "threshold": 3},
            "files_created": {"weight": 2, "threshold": 1},
            "registry_written": {"weight": 2, "threshold": 1},
            "api_category_network_count": {"weight": 2, "threshold": 1},
            "dropped_executable_count": {"weight": 4, "threshold": 1},
            "dropped_script_count": {"weight": 3, "threshold": 1},
        },
    },

    "credential_theft": {
        "display_name": "Credential Theft / Information Stealing",
        "description": (
            "This category indicates possible credential theft or information stealing behavior, "
            "such as network communication, registry access, file access, or form-based phishing indicators."
        ),
        "evidence": {
            "Acroform": {"weight": 2, "threshold": 1},
            "AcroForm": {"weight": 2, "threshold": 1},
            "URI": {"weight": 2, "threshold": 1},
            "http_requests": {"weight": 3, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "domains_count": {"weight": 2, "threshold": 1},
            "files_read": {"weight": 1, "threshold": 5},
            "registry_read": {"weight": 1, "threshold": 5},
        },
    },

    "spyware": {
        "display_name": "Spyware / Surveillance Behavior",
        "description": (
            "This category indicates possible spyware-like behavior such as information gathering, "
            "registry inspection, file access, or outbound communication."
        ),
        "evidence": {
            "files_read": {"weight": 2, "threshold": 5},
            "registry_read": {"weight": 2, "threshold": 5},
            "registry_keys_touched": {"weight": 2, "threshold": 5},
            "api_category_network_count": {"weight": 2, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "http_requests": {"weight": 2, "threshold": 1},
        },
    },

    "dropper_payload_delivery": {
        "display_name": "Dropper / Payload Delivery",
        "description": (
            "This category indicates that the PDF may have dropped or extracted a secondary payload "
            "such as a script, executable, or macro-capable Office document."
        ),
        "evidence": {
            "dropped_office_macro_count": {"weight": 4, "threshold": 1},
            "dropped_script_count": {"weight": 4, "threshold": 1},
            "dropped_executable_count": {"weight": 5, "threshold": 1},
            "temp_suspicious_file_created": {"weight": 3, "threshold": 1},
            "pdf_extracted_embedded_payload": {"weight": 3, "threshold": 1},
            "files_created": {"weight": 1, "threshold": 1},
        },
    },

    "c2_communication": {
        "display_name": "Command and Control / C2 Communication",
        "description": (
            "This category indicates possible command-and-control communication, "
            "such as DNS lookups, HTTP requests, or repeated outbound network activity."
        ),
        "evidence": {
            "tcp_conn": {"weight": 2, "threshold": 1},
            "http_requests": {"weight": 3, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "domains_count": {"weight": 2, "threshold": 1},
            "hosts_count": {"weight": 2, "threshold": 1},
            "api_category_network_count": {"weight": 3, "threshold": 1},
        },
    },

    "download_execute": {
        "display_name": "Download and Execute Behavior",
        "description": (
            "This category indicates behavior consistent with downloading or launching a secondary payload."
        ),
        "evidence": {
            "http_requests": {"weight": 3, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "files_created": {"weight": 2, "threshold": 1},
            "has_temp_exe_execution": {"weight": 5, "threshold": 1},
            "dropped_executable_count": {"weight": 5, "threshold": 1},
            "dropped_script_count": {"weight": 3, "threshold": 1},
        },
    },

    "defense_evasion": {
        "display_name": "Defense Evasion / Obfuscation",
        "description": (
            "This category indicates suspicious behavior or structure that may be used to evade detection, "
            "such as object streams, encryption, JavaScript triggers, or debugger checks."
        ),
        "evidence": {
            "ObjStm": {"weight": 2, "threshold": 1},
            "encrypt": {"weight": 2, "threshold": 1},
            "isEncrypted": {"weight": 2, "threshold": 1},
            "JS": {"weight": 3, "threshold": 1},
            "JavaScript": {"weight": 3, "threshold": 1},
            "OpenAction": {"weight": 3, "threshold": 1},
            "suspicious_api_calls": {"weight": 2, "threshold": 50},
        },
    },

    "lateral_movement": {
        "display_name": "Lateral Movement / Internal Propagation",
        "description": (
            "This category indicates possible lateral movement or internal propagation behavior. "
            "In this prototype, evidence is limited and should be reviewed carefully."
        ),
        "evidence": {
            "api_category_network_count": {"weight": 2, "threshold": 10},
            "tcp_conn": {"weight": 2, "threshold": 3},
            "process_count": {"weight": 1, "threshold": 5},
            "suspicious_api_calls": {"weight": 2, "threshold": 70},
        },
    },

    "data_exfiltration": {
        "display_name": "Data Exfiltration",
        "description": (
            "This category indicates possible data exfiltration behavior through outbound network activity "
            "or suspicious file access followed by network communication."
        ),
        "evidence": {
            "http_requests": {"weight": 3, "threshold": 1},
            "dns_requests": {"weight": 2, "threshold": 1},
            "domains_count": {"weight": 2, "threshold": 1},
            "api_category_network_count": {"weight": 3, "threshold": 1},
            "files_read": {"weight": 1, "threshold": 5},
            "files_touched": {"weight": 1, "threshold": 10},
        },
    },

    "macro_payload_delivery": {
        "display_name": "Macro Payload Delivery",
        "description": (
            "This category indicates that the PDF extracted or delivered an Office macro-capable document, "
            "such as DOCM, XLSM, or PPTM."
        ),
        "evidence": {
            "dropped_office_macro_count": {"weight": 5, "threshold": 1},
            "temp_suspicious_file_created": {"weight": 3, "threshold": 1},
            "pdf_extracted_embedded_payload": {"weight": 3, "threshold": 1},
        },
    },
}

REPORTED_INCIDENT_MAP = {
    "unknown": None,

    "data_loss_or_missing_files": "ransomware_activity",
    "unauthorized_file_modification": "ransomware_activity",
    "suspicious_file_creation": "dropper_payload_delivery",

    "data_exfiltration_suspected": "data_exfiltration",
    "unauthorized_network_activity": "c2_communication",
    "credential_theft_suspected": "credential_theft",

    "unauthorized_access": "suspicious_process_behavior",
    "persistence_suspected": "persistence_activity",
    "malware_execution_suspected": "trojan_behavior",
    "process_injection_suspected": "process_injection",
    "suspicious_process_activity": "suspicious_process_behavior",

    "system_configuration_change": "persistence_activity",
    "registry_modification_suspected": "persistence_activity",

    "phishing_or_social_engineering": "phishing",
    "payload_delivery_suspected": "dropper_payload_delivery",
    "ransomware_like_activity": "ransomware_activity",
}

# =========================================================
# 2) Static Indicators
# =========================================================
# هذه تستخدم فقط لتدعيم التفسير، وليس للحكم النهائي وحدها.
# لأنها تدل على malicious intent حتى لو لم يحدث detonation.
# =========================================================

STATIC_TRIGGER_FEATURES = [
    "JS",
    "JavaScript",
    "AA",
    "OpenAction",
    "Acroform",
    "AcroForm",
    "JBIG2Decode",
    "RichMedia",
    "launch",
    "Launch",
    "EmbeddedFile",
    "embedded_files",
    "XFA",
    "URI",
    "ObjStm",
    "encrypt",
    "isEncrypted",
]


# =========================================================
# 3) Helper Functions
# =========================================================

def safe_float(value):
    """
    يحوّل أي قيمة إلى float بطريقة آمنة.
    إذا كانت القيمة غير صالحة يرجع 0.
    """
    try:
        if value is None:
            return 0.0
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def get_feature_value(features, feature_name):
    """
    يرجع قيمة feature من dictionary.
    إذا غير موجودة يرجع 0.
    """
    if not isinstance(features, dict):
        return 0.0

    return safe_float(features.get(feature_name, 0))


def detect_static_triggers(static_features):
    """
    يبحث عن static indicators مثل JavaScript / OpenAction / EmbeddedFile.
    يرجع قائمة بالمؤشرات الموجودة.
    """
    triggers = []

    if not isinstance(static_features, dict):
        return triggers

    for feature in STATIC_TRIGGER_FEATURES:
        value = get_feature_value(static_features, feature)
        if value > 0:
            triggers.append({
                "feature": feature,
                "value": value
            })

    return triggers


def calculate_confidence(score, max_score):
    """
    يحوّل score إلى مستوى ثقة نصي.
    """
    if max_score <= 0:
        return "None"

    ratio = score / max_score

    if ratio >= 0.75:
        return "High"
    elif ratio >= 0.40:
        return "Medium"
    elif ratio > 0:
        return "Low"
    else:
        return "None"


def calculate_correlation_score(features, rule):
    """
    يحسب correlation score لكل incident بناءً على الـ evidence rules.
    """
    total_score = 0
    max_score = 0
    matched_evidence = []

    evidence_rules = rule.get("evidence", {})

    for feature_name, condition in evidence_rules.items():
        weight = condition.get("weight", 1)
        threshold = condition.get("threshold", 1)

        max_score += weight

        value = get_feature_value(features, feature_name)

        if value >= threshold:
            total_score += weight

            matched_evidence.append({
                "feature": feature_name,
                "value": value,
                "threshold": threshold,
                "weight": weight
            })

    Correlation_Strength = calculate_confidence(total_score, max_score)

    return {
        "score": total_score,
        "max_score": max_score,
        "Correlation Strength": Correlation_Strength,
        "matched_evidence": matched_evidence
    }


def build_culpability_verdict(
    hybrid_result=None,
    incident_matches=None,
    static_triggers=None
):
    """
    يحدد هل الملف مسؤول/مرتبط بالحالة أم لا.

    مهم:
    هذا الحكم ليس malware classification فقط.
    هذا حكم forensic causality:
    هل يوجد دليل كافي أن هذا الملف تسبب أو ساهم في الحادث؟
    """

    if incident_matches is None:
        incident_matches = []

    if static_triggers is None:
        static_triggers = []

    hybrid_verdict = ""
    runtime_verdict = ""
    static_label = ""
    dynamic_label = ""

    if isinstance(hybrid_result, dict):
        hybrid_verdict = str(hybrid_result.get("hybrid_verdict", ""))
        runtime_verdict = str(hybrid_result.get("runtime_verdict", ""))
        static_label = str(hybrid_result.get("static_label", ""))
        dynamic_label = str(hybrid_result.get("dynamic_label", ""))

    has_high_incident_match = any(
        match.get("Correlation Strength") == "High" for match in incident_matches
    )

    has_medium_incident_match = any(
        match.get("Correlation Strength") == "Medium" for match in incident_matches
    )

    has_any_incident_match = len(incident_matches) > 0
    has_static_triggers = len(static_triggers) > 0

        # =====================================================
    # 0) Clean benign case:
    # إذا كل طبقات التحليل تقول benign/no runtime evidence，
    # لا نعتبر activity البيئة كحادث جنائي.
    # =====================================================
    if (
        static_label == "Benign"
        and dynamic_label == "Benign"
        and "No Strong Runtime Evidence" in runtime_verdict
    ):
        return {
            "culpability": "Not Correlated",
            "Correlation Strength": "Low",
            "explanation": (
                "Both static and dynamic analysis classified the file as benign, and no strong "
                "runtime malicious evidence was observed. Any low-level activity is treated as "
                "normal environment or PDF reader behavior."
            )
        }

    # =====================================================
    # 1) أهم قاعدة:
    # إذا الملف Static Malicious لكن Runtime لم يظهر سلوك قوي，
    # لا يجوز اعتباره Culpable حتى لو ظهرت network/file/process activity.
    # لأن هذه قد تكون environment noise أو non-triggered payload.
    # =====================================================
    if (
        static_label == "Malicious"
        and "No Strong Runtime Evidence" in runtime_verdict
    ):
        return {
            "culpability": "Potentially Malicious / No Confirmed Runtime Causality",
            "Correlation Strength": "Medium" if has_static_triggers else "Low",
            "explanation": (
                "The PDF contains structural indicators of malicious intent, but no strong runtime "
                "behavior was observed. Therefore, the file should be treated as potentially malicious, "
                "but there is not enough behavioral evidence to prove that it caused the incident in "
                "the current execution environment."
            )
        }

    # =====================================================
    # 2) إذا الـ hybrid verdict نفسه Dormant، لا نعتبره Culpable
    # حتى لو فيه incident matches مبنية على raw activity.
    # =====================================================
    if "Dormant Malicious" in hybrid_verdict:
        return {
            "culpability": "Potentially Malicious / Dormant or Non-Triggered",
            "Correlation Strength": "Medium" if has_static_triggers else "Low",
            "explanation": (
                "The PDF was classified as structurally malicious, but the dynamic analysis did not "
                "confirm active malicious execution. This suggests a dormant, evasive, or non-triggered "
                "payload rather than confirmed incident causality."
            )
        }

    # =====================================================
    # 3) أقوى حالة:
    # Strong runtime evidence + high incident match
    # =====================================================
    if (
        "Strong Dynamic Malicious Evidence" in runtime_verdict
        and has_high_incident_match
    ):
        return {
            "culpability": "Culpable / Strongly Correlated",
            "Correlation Strength": "High",
            "explanation": (
                "The PDF is strongly correlated with the incident because strong runtime malicious "
                "behavior was observed and the behavioral evidence matches the incident pattern."
            )
        }

    # =====================================================
    # 4) Dynamic model malicious + incident match
    # بشرط ألا يكون runtime = No Strong Runtime Evidence
    # =====================================================
    if (
        dynamic_label == "Malicious"
        and has_any_incident_match
        and "No Strong Runtime Evidence" not in runtime_verdict
    ):
        return {
            "culpability": "Culpable / Behaviorally Correlated",
            "Correlation Strength": "High" if has_high_incident_match else "Medium",
            "explanation": (
                "The dynamic analysis indicates malicious behavior that aligns with one or more "
                "incident categories."
            )
        }

    # =====================================================
    # 5) Matches موجودة لكن بدون strong runtime evidence
    # =====================================================
    if has_medium_incident_match or has_high_incident_match:
        return {
            "culpability": "Possibly Correlated / Requires Analyst Review",
            "Correlation Strength": "Medium",
            "explanation": (
                "Some behavioral indicators match known incident patterns, but the evidence is not "
                "strong enough to establish clear causality. Analyst review is required."
            )
        }

    # =====================================================
    # 6) Static triggers فقط
    # =====================================================
    if has_static_triggers:
        return {
            "culpability": "Suspicious Static Intent / No Incident Correlation",
            "Correlation Strength": "Low",
            "explanation": (
                "Static suspicious indicators were found, but the observed runtime behavior does not "
                "clearly correlate with a specific incident category."
            )
        }

    # =====================================================
    # 7) لا يوجد ربط
    # =====================================================
    return {
        "culpability": "Not Correlated",
        "Correlation Strength": "Low",
        "explanation": (
            "No sufficient static or dynamic evidence was found to correlate the PDF with a known "
            "incident scenario."
        )
    }


def generate_forensic_summary(
    incident_matches,
    static_triggers,
    culpability_result,
    suppress_incident_matches=False
):
    """
    يولد summary نصي مختصر يصلح عرضه في log أو report.
    """

    lines = []

    lines.append("Forensic Correlation Summary")
    lines.append("=" * 35)

    lines.append(f"Culpability Verdict: {culpability_result.get('culpability')}")
    lines.append(f"Correlation Strength: {culpability_result.get('Correlation Strength')}")
    lines.append(f"Reasoning: {culpability_result.get('explanation')}")
    lines.append("")

    if static_triggers:
        lines.append("Static Indicators:")
        for item in static_triggers:
            lines.append(f"- {item['feature']} = {item['value']}")
        lines.append("")
    else:
        lines.append("Static Indicators: None detected")
        lines.append("")
    
    if suppress_incident_matches:
        lines.append("Matched Incident Categories:")
        lines.append(
            "- Suppressed: no confirmed runtime causality was observed in the current environment."
        )

        culpability_label = str(culpability_result.get("culpability", ""))

        if "Not Correlated" in culpability_label:
            lines.append(
                "- The observed activity is treated as normal environment noise or PDF reader behavior."
            )
        else:
            lines.append(
                "- The observed activity may represent environment noise, PDF reader behavior, or a non-triggered payload."
            )

        lines.append("")
        return "\n".join(lines)
    
    if incident_matches:
        lines.append("Matched Incident Categories:")
        for match in incident_matches:
            lines.append(
                f"- {match['display_name']} "
                f"| Correlation Strength: {match['Correlation Strength']} "
                f"| Score: {match['score']}/{match['max_score']}"
            )

            for evidence in match.get("matched_evidence", []):
                lines.append(
                    f"  * {evidence['feature']} = {evidence['value']} "
                    f"(threshold: {evidence['threshold']}, weight: {evidence['weight']})"
                )

        lines.append("")
    else:
        lines.append("Matched Incident Categories: None")
        lines.append("")

    return "\n".join(lines)


# =========================================================
# 4) Main Function
# =========================================================

def correlate_incident(
    dynamic_features,
    static_result=None,
    hybrid_result=None,
    reported_incident_type="unknown",
    min_score=1
):
    """
    الدالة الرئيسية التي ستستدعيها من dynamic_test_app.py.

    Parameters:
        dynamic_features: dict
            features_used أو all_features من dynamic analysis.

        static_result: dict optional
            نتيجة static analysis وفيها static_features.

        hybrid_result: dict optional
            نتيجة evaluate_hybrid_verdict.

        min_score: int
            أقل score لقبول incident match.

    Returns:
        dict فيه:
            - incident_matches
            - static_triggers
            - culpability
            - summary
    """

    if dynamic_features is None:
        dynamic_features = {}

    static_features = {}

    if isinstance(static_result, dict):
        static_features = static_result.get("static_features", {}) or {}
    
    combined_features = {}

    if isinstance(dynamic_features, dict):
        combined_features.update(dynamic_features)

    if isinstance(static_features, dict):
        combined_features.update(static_features)

    static_triggers = detect_static_triggers(static_features)

    incident_matches = []

    runtime_verdict = ""
    static_label = ""
    dynamic_label = ""

    if isinstance(hybrid_result, dict):
        runtime_verdict = str(hybrid_result.get("runtime_verdict", ""))
        static_label = str(hybrid_result.get("static_label", ""))
        dynamic_label = str(hybrid_result.get("dynamic_label", ""))

    suppress_incident_matches = (
        (
            static_label == "Malicious"
            and "No Strong Runtime Evidence" in runtime_verdict
        )
        or
        (
            static_label == "Benign"
            and dynamic_label == "Benign"
            and "No Strong Runtime Evidence" in runtime_verdict
        )
    )
    
    if not suppress_incident_matches:
        reported_incident_type = str(reported_incident_type or "unknown").lower()
        selected_rule_id = REPORTED_INCIDENT_MAP.get(reported_incident_type)

        if selected_rule_id is not None:
            rules_to_check = {
                selected_rule_id: INCIDENT_RULES[selected_rule_id]
            }
        else:
            rules_to_check = INCIDENT_RULES

        for incident_id, rule in rules_to_check.items():
            result = calculate_correlation_score(combined_features, rule)

            if result["score"] >= min_score:
                incident_matches.append({
                    "incident_id": incident_id,
                    "display_name": rule.get("display_name", incident_id),
                    "description": rule.get("description", ""),
                    "score": result["score"],
                    "max_score": result["max_score"],
                    "Correlation Strength": result["Correlation Strength"],
                    "matched_evidence": result["matched_evidence"],
                })

    # ترتيب النتائج من الأقوى للأضعف
    incident_matches = sorted(
        incident_matches,
        key=lambda x: (x["score"], x["max_score"]),
        reverse=True
    )
    if str(reported_incident_type).lower() == "unknown":
        incident_matches = incident_matches[:5]
    
    # =====================================================
    # Reduce noisy incident categories when runtime evidence
    # is only moderate or weak.
    # =====================================================
    if (
        "Runtime Behavior Observed - Moderate Suspicion" in runtime_verdict
        or "Runtime Behavior Observed - Weak Suspicion" in runtime_verdict
    ):
        allowed_incidents = {
            "process_injection",
            "suspicious_process_behavior",
        }
    
        incident_matches = [
            match for match in incident_matches
            if match.get("incident_id") in allowed_incidents
        ]

    culpability_result = build_culpability_verdict(
        hybrid_result=hybrid_result,
        incident_matches=incident_matches,
        static_triggers=static_triggers
    )

    summary = generate_forensic_summary(
        incident_matches=incident_matches,
        static_triggers=static_triggers,
        culpability_result=culpability_result,
        suppress_incident_matches=suppress_incident_matches
    )

    return {
        "reported_incident_type": reported_incident_type,
        "incident_matches": incident_matches,
        "static_triggers": static_triggers,
        "culpability": culpability_result,
        "summary": summary
    }


# =========================================================
# 5) Standalone Test
# =========================================================
# هذا الجزء يعمل فقط إذا شغلت الملف مباشرة.
# لا يؤثر على app الأساسي.
# =========================================================

if __name__ == "__main__":
    sample_dynamic_features = {
        "tcp_conn": 4,
        "udp_conn": 0,
        "http_requests": 1,
        "dns_requests": 3,
        "domains_count": 2,
        "api_category_network_count": 120,

        "files_created": 5,
        "files_deleted": 1,
        "api_category_file_count": 80,

        "registry_written": 0,
        "registry_keys_touched": 0,
        "api_category_registry_count": 0,

        "api_writeprocessmemory_count": 0,
        "api_createremotethread_count": 0,
        "api_virtualprotectex_count": 0,
        "api_ntallocatevirtualmemory_count": 0,
        "api_ldrloaddll_count": 0,
        "has_temp_exe_execution": 0,

        "process_count": 11,
        "suspicious_api_calls": 5,
        "api_category_process_count": 523,
    }

    sample_static_result = {
        "static_label": "Malicious",
        "static_probability": 0.95,
        "static_features": {
            "JS": 1,
            "JavaScript": 1,
            "OpenAction": 1,
            "EmbeddedFile": 0,
            "URI": 0,
        }
    }

    sample_hybrid_result = {
        "hybrid_verdict": "Likely Malicious - No Strong Runtime Detonation",
        "runtime_verdict": "No Strong Runtime Evidence",
        "static_label": "Malicious",
        "dynamic_label": "Benign",
    }

    result = correlate_incident(
        dynamic_features=sample_dynamic_features,
        static_result=sample_static_result,
        hybrid_result=sample_hybrid_result
    )

    print(result["summary"])