import re

from cpo.Detector.signature import * # type: ignore


# =====================================================
# SINGLE PAYLOAD SCAN
# =====================================================

def scan_payload(payload):

    exact_matches = []

    regex_matches = []

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
    # TOTAL MATCHES
    # =================================================

    total_matches = (
        len(exact_matches)
        + len(regex_matches)
    )

    # =================================================
    # DETECTION STATUS
    # =================================================

    detection_status = (
        "DETECTED"
        if total_matches > 0
        else "BYPASSED"
    )

    # =================================================
    # RISK LEVEL
    # =================================================

    risk_level = "Unknown"

    for threshold, level in sorted(
        RISK_LEVELS.items(), # type: ignore
        reverse=True
    ):

        if total_matches >= threshold:

            risk_level = level
            break

    # =================================================
    # RETURN RESULTS
    # =================================================

    return {

        "status": detection_status,

        "risk": risk_level,

        "exact_matches": exact_matches,

        "regex_matches": regex_matches,

        "total_matches": total_matches
    }


# =====================================================
# COMPARATIVE DETECTION ENGINE
# =====================================================

def compare_payloads(

    original_payload,
    obfuscated_payload,
    encoded_payload

):

    results = {

        "Original Payload":
            scan_payload(original_payload),

        "Obfuscated Payload":
            scan_payload(obfuscated_payload),

        "Encoded Payload":
            scan_payload(encoded_payload)
    }

    return results


# =====================================================
# GENERATE COMPARATIVE REPORT
# =====================================================

def generate_comparison_report(results):

    report = []

    report.append(
        "========================================"
    )

    report.append(
        " Comparative Detection Report"
    )

    report.append(
        "========================================\n"
    )

    # =================================================
    # EACH PAYLOAD RESULT
    # =================================================

    for payload_type, data in results.items():

        report.append(
            f"{payload_type}"
        )

        report.append(
            "-" * len(payload_type)
        )

        report.append(
            f"Detection Status: "
            f"{data['status']}"
        )

        report.append(
            f"Risk Level: "
            f"{data['risk']}"
        )

        report.append(
            f"Total Matches: "
            f"{data['total_matches']}"
        )

        # =============================================
        # EXACT MATCHES
        # =============================================

        report.append("\nExact Matches:")

        if data["exact_matches"]:

            for match in data["exact_matches"]:

                report.append(f"- {match}")

        else:

            report.append("None")

        # =============================================
        # REGEX MATCHES
        # =============================================

        report.append("\nRegex Matches:")

        if data["regex_matches"]:

            for match in data["regex_matches"]:

                report.append(f"- {match}")

        else:

            report.append("None")

        report.append("\n")

    # =================================================
    # EVASION INSIGHTS
    # =================================================

    report.append(
        "========================================"
    )

    report.append(
        " Evasion Insights"
    )

    report.append(
        "========================================\n"
    )

    original_detected = (
        results["Original Payload"]["status"]
        == "DETECTED"
    )

    obfuscated_bypassed = (
        results["Obfuscated Payload"]["status"]
        == "BYPASSED"
    )

    encoded_bypassed = (
        results["Encoded Payload"]["status"]
        == "BYPASSED"
    )

    if original_detected:

        report.append(
            "- Original payload triggered "
            "static signature detection."
        )

    if obfuscated_bypassed:

        report.append(
            "- Obfuscation reduced visible "
            "signature patterns."
        )

    if encoded_bypassed:

        report.append(
            "- Encoding hid suspicious "
            "readable strings."
        )

    if (
        not obfuscated_bypassed
        and not encoded_bypassed
    ):

        report.append(
            "- Transformations were not "
            "sufficient to bypass detection."
        )

    report.append("\n")

    return "\n".join(report)