from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"

DB_PATH = RESULTS_DIR / "campus_audit.db"
CSV_REPORT_PATH = RESULTS_DIR / "audit_findings_sample.csv"

# Display paths (sanitized for terminal & audit workpapers)
DISPLAY_DB_PATH = "results/campus_audit.db"
DISPLAY_CSV_PATH = "results/audit_findings_sample.csv"

# Audit Thresholds & Settings
OFF_HOURS_START = 0  # 00:00 (Midnight)
OFF_HOURS_END = 4    # Through 04:59 AM
BRUTE_FORCE_THRESHOLD = 4

SENSITIVE_RESOURCES = (
    "Financial_Aid_Master_DB",
    "Payroll_Admin_Portal",
    "Student_SSN_Registry",
    "Active_Directory_Domain_Controller",
)
