import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import app as scamshield


def disable_external_providers():
    scamshield.google_safe_browsing_check = lambda url: (None, "Google Safe Browsing disabled during dataset evaluation.")
    scamshield.phishtank_check = lambda url: (None, "PhishTank disabled during dataset evaluation.")
    scamshield.domain_age_check = lambda domain: (None, None, "Domain age lookup disabled during dataset evaluation.")
    scamshield.virus_total_check = lambda url: (None, None, "VirusTotal disabled during dataset evaluation.")


def risk_band(percent):
    if percent >= 75:
        return "high"
    if percent >= 45:
        return "medium"
    return "low"


def main():
    disable_external_providers()
    dataset_path = Path(__file__).resolve().parent / "data" / "sample_messages.json"
    samples = json.loads(dataset_path.read_text(encoding="utf-8"))

    category_hits = 0
    risk_hits = 0
    results = []

    for sample in samples:
        summary, explanation, link_reports, provider_statuses, explainability, recommended_actions, iocs, evidence_breakdown = scamshield.run_scan(
            sample["input"],
            include_vt=False,
        )
        actual_category = summary["scam_type"]
        actual_risk = risk_band(summary["risk_percent"])

        category_match = actual_category == sample["expected_category"]
        risk_match = actual_risk == sample["expected_risk"]
        category_hits += int(category_match)
        risk_hits += int(risk_match)

        results.append({
            "id": sample["id"],
            "expected_category": sample["expected_category"],
            "actual_category": actual_category,
            "expected_risk": sample["expected_risk"],
            "actual_risk": actual_risk,
            "risk_percent": summary["risk_percent"],
            "category_match": category_match,
            "risk_match": risk_match,
        })

    total = len(samples)
    print(f"Dataset samples: {total}")
    print(f"Category matches: {category_hits}/{total}")
    print(f"Risk band matches: {risk_hits}/{total}")
    print()

    for item in results:
        if not item["category_match"] or not item["risk_match"]:
            print(
                f"[{item['id']}] category {item['expected_category']} -> {item['actual_category']} | "
                f"risk {item['expected_risk']} -> {item['actual_risk']} ({item['risk_percent']}%)"
            )


if __name__ == "__main__":
    main()
