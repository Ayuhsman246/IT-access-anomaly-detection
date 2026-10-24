import csv
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter
from src.config import DISPLAY_DB_PATH, DISPLAY_CSV_PATH

FIELDNAMES = [
    "finding_id",
    "control_id",
    "control_name",
    "severity",
    "user_id",
    "username",
    "department",
    "role",
    "resource",
    "timestamp",
    "ip_address",
    "evidence_description",
]


def export_findings_to_csv(findings: List[Dict[str, Any]], csv_path: Path) -> None:
    """Writes all audit findings to a structured CSV workpaper."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(findings)


def print_executive_summary(
    total_users: int,
    total_logs: int,
    findings: List[Dict[str, Any]],
) -> None:
    """Prints a formatted audit execution summary to the console using clean relative paths."""
    severity_counts = Counter(f["severity"] for f in findings)

    print("=" * 88)
    print("  IT ACCESS ANOMALY DETECTION & ITGC AUDIT ENGINE")
    print("=" * 88)
    print(f"  [+] Database Generated : {DISPLAY_DB_PATH}")
    print(f"  [+] CSV Report Exported: {DISPLAY_CSV_PATH}")
    print(f"  [+] Scope Analyzed     : {total_users} User Identities | {total_logs} Access Events")
    print("-" * 88)
    print(
        f"  SUMMARY BY SEVERITY    : "
        f"CRITICAL: {severity_counts.get('CRITICAL', 0)} | "
        f"HIGH: {severity_counts.get('HIGH', 0)} | "
        f"MEDIUM: {severity_counts.get('MEDIUM', 0)} | "
        f"TOTAL FINDINGS: {len(findings)}"
    )
    print("=" * 88)
    print(f"{'ID':<8} {'CTRL':<8} {'SEVERITY':<10} {'USER':<10} {'RESOURCE':<34} {'TIMESTAMP':<19}")
    print("-" * 88)

    for f in findings:
        res_short = (f["resource"][:31] + "...") if len(f["resource"]) > 31 else f["resource"]
        print(
            f"{f['finding_id']:<8} "
            f"{f['control_id']:<8} "
            f"{f['severity']:<10} "
            f"{f['username']:<10} "
            f"{res_short:<34} "
            f"{f['timestamp']:<19}"
        )
    print("=" * 88)
