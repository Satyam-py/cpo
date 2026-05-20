import re
import math
from collections import Counter
from pathlib import Path

from cpo.Detector.signature import * # type: ignore


# =====================================================
# SHANNON ENTROPY
# =====================================================

def calculate_entropy(data):

    if not data:
        return 0

    counter = Counter(data)

    length = len(data)

    entropy = 0

    for count in counter.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


# =====================================================
# SUSPICIOUS CHARACTER ANALYSIS
# =====================================================

def suspicious_char_ratio(payload):

    suspicious_chars = r"[@#$%^&*(){}\\|<>]"

    matches = re.findall(
        suspicious_chars,
        payload
    )

    if not payload:
        return 0

    ratio = (
        len(matches) / len(payload)
    ) * 100

    return round(ratio, 2)


# =====================================================
# STRING FRAGMENTATION DETECTION
# =====================================================

def detect_fragmentation(payload):

    fragmentation_patterns = [

        r'"\s*\+\s*"',      # "ab" + "cd"
        r"'\s*\+\s*'",      # 'ab' + 'cd'
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}"
    ]

    matches = 0

    for pattern in fragmentation_patterns:

        matches += len(
            re.findall(pattern, payload)
        )

    return matches


# =====================================================
# SINGLE PAYLOAD SCAN
# =====================================================

def scan_payload(payload):

    exact_matches = []

    regex_matches = []

    analysis_notes = []

    # =================================================
    # EXACT SIGNATURE MATCHING
    # =================================================

    for signature in EXACT_SIGNATURES: # type: ignore

        if signature.lower() in payload.lower():

            exact_matches.append(signature)

    # =================================================
    # REGEX / HEURISTIC MATCHING
    # =================================================

    for name, pattern in REGEX_SIGNATURES.items(): # type: ignore

        if re.search(
            pattern,
            payload,
            re.IGNORECASE
        ):

            regex_matches.append(name)

    # =================================================
    # ADVANCED ANALYSIS
    # =================================================

    entropy = calculate_entropy(payload)

    fragmentation_score = detect_fragmentation(
        payload
    )

    suspicious_ratio = suspicious_char_ratio(
        payload
    )

    payload_size = len(payload)

    # =================================================
    # ANALYSIS NOTES
    # =================================================

    if entropy >= 4.5:

        analysis_notes.append(
            "High entropy detected "
            "(possible encoding/encryption)"
        )

    if fragmentation_score >= 2:

        analysis_notes.append(
            "String fragmentation patterns found"
        )

    if suspicious_ratio >= 5:

        analysis_notes.append(
            "High suspicious character ratio"
        )

    if payload_size >= 5000:

        analysis_notes.append(
            "Large payload size"
        )

    # =================================================
    # TOTAL MATCHES
    # =================================================

    total_matches = (

        len(exact_matches)

        + len(regex_matches)

        + fragmentation_score
    )

    # =================================================
    # DETECTION STATUS
    # =================================================

    if total_matches == 0:

        detection_status = "BYPASSED"

    elif total_matches <= 2:

        detection_status = "PARTIALLY DETECTED"

    else:

        detection_status = "DETECTED"

    # =================================================
    # RISK LEVEL
    # =================================================

    if total_matches >= 6:

        risk_level = "Critical"

    elif total_matches >= 4:

        risk_level = "High"

    elif total_matches >= 2:

        risk_level = "Medium"

    else:

        risk_level = "Low"

    # =================================================
    # RETURN RESULTS
    # =================================================

    return {

        "status": detection_status,

        "risk": risk_level,

        "exact_matches": exact_matches,

        "regex_matches": regex_matches,

        "analysis_notes": analysis_notes,

        "entropy": entropy,

        "fragmentation_score": fragmentation_score,

        "suspicious_ratio": suspicious_ratio,

        "payload_size": payload_size,

        "total_matches": total_matches
    }


# =====================================================
# COMPARATIVE DETECTION ENGINE
# =====================================================

def compare_payloads(

    original_payload,
    obfuscated_payload,
    encoded_payload,

    original_file,
    obfuscated_file,
    encoded_file

):

    results = {

        "Original Payload": {

            "file_name": Path(original_file).name,

            **scan_payload(original_payload)
        },

        "Obfuscated Payload": {

            "file_name": obfuscated_file,

            **scan_payload(obfuscated_payload)
        },

        "Encoded Payload": {

            "file_name": encoded_file,

            **scan_payload(encoded_payload)
        }
    }
    return results


# =====================================================
# GENERATE REPORT
# =====================================================

def generate_comparison_report(results):

    report = []

    report.append(
        "=" * 60
    )

    report.append(
        "        CPO Comparative Detection Report"
    )

    report.append(
        "=" * 60 + "\n"
    )

    # =================================================
    # PAYLOAD RESULTS
    # =================================================

    for payload_type, data in results.items():

        report.append(
            f"{payload_type}"
        )

        report.append(
            f"File Name      : "
            f"{data['file_name']}"
        )
        report.append(
            "-" * len(payload_type)
        )

        report.append(
            f"Detection Status : {data['status']}"
        )

        report.append(
            f"Risk Level      : {data['risk']}"
        )

        report.append(
            f"Total Matches   : {data['total_matches']}"
        )

        report.append(
            f"Entropy Score   : {data['entropy']}"
        )

        report.append(
            f"Fragmentation   : "
            f"{data['fragmentation_score']}"
        )

        report.append(
            f"Suspicious Ratio: "
            f"{data['suspicious_ratio']}%"
        )

        report.append(
            f"Payload Size    : "
            f"{data['payload_size']} bytes"
        )

        # =============================================
        # EXACT MATCHES
        # =============================================

        report.append("\n[ Exact Matches ]")

        if data["exact_matches"]:

            for match in data["exact_matches"]:

                report.append(f"  - {match}")

        else:

            report.append("  None")

        # =============================================
        # REGEX MATCHES
        # =============================================

        report.append("\n[ Regex Matches ]")

        if data["regex_matches"]:

            for match in data["regex_matches"]:

                report.append(f"  - {match}")

        else:

            report.append("  None")

        # =============================================
        # ANALYSIS NOTES
        # =============================================

        report.append("\n[ Analysis Notes ]")

        if data["analysis_notes"]:

            for note in data["analysis_notes"]:

                report.append(f"  - {note}")

        else:

            report.append("  None")

        report.append("\n")

    # =================================================
    # EVASION INSIGHTS
    # =================================================

    report.append(
        "=" * 60
    )

    report.append(
        "               Evasion Insights"
    )

    report.append(
        "=" * 60 + "\n"
    )

    original = results["Original Payload"]
    obfuscated = results["Obfuscated Payload"]
    encoded = results["Encoded Payload"]

    if (

        obfuscated["total_matches"]
        < original["total_matches"]

    ):

        report.append(
            "- Obfuscation reduced "
            "detectable signatures."
        )

    else:

        report.append(
            "- Obfuscation did not "
            "significantly reduce detection."
        )

    if (

        encoded["entropy"]
        > original["entropy"]

    ):

        report.append(
            "- Encoding increased "
            "payload entropy."
        )

    if (

        obfuscated["fragmentation_score"]
        > 0

    ):

        report.append(
            "- Obfuscation introduced "
            "fragmented string patterns."
        )

    if (

        encoded["status"] == "BYPASSED"
        or obfuscated["status"] == "BYPASSED"

    ):

        report.append(
            "- One or more payloads bypassed "
            "basic signature analysis."
        )

    report.append("\n")

    return "\n".join(report)