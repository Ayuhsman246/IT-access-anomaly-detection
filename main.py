from src.config import DB_PATH, CSV_REPORT_PATH
from src.database import init_database, seed_synthetic_data
from src.detector import run_all_audit_controls
from src.reporter import export_findings_to_csv, print_executive_summary


def main() -> None:
    conn = init_database(DB_PATH)
    seed_synthetic_data(conn)

    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_logs = conn.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0]

    findings = run_all_audit_controls(conn)

    export_findings_to_csv(findings, CSV_REPORT_PATH)
    print_executive_summary(total_users, total_logs, findings)

    conn.close()


if __name__ == "__main__":
    main()
