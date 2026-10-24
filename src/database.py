import sqlite3
from pathlib import Path
from typing import List, Tuple


def init_database(db_path: Path) -> sqlite3.Connection:
    """Initializes the SQLite database and creates tables."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE users (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            termination_date TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE access_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            resource TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            location TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    """)

    conn.commit()
    return conn


def seed_synthetic_data(conn: sqlite3.Connection) -> None:
    """Populates the database with realistic baseline traffic and deterministic ITGC audit anomalies."""
    cursor = conn.cursor()

    users: List[Tuple] = [
        ("U1001", "jdoe", "John Doe", "IT Security", "SysAdmin", "Active", None),
        ("U1002", "asmith", "Alice Smith", "Finance", "Senior Accountant", "Active", None),
        ("U1003", "rmiller", "Robert Miller", "Facilities", "Contractor", "Terminated", "2026-09-15"),
        ("U1004", "tchen", "Thomas Chen", "Library", "Student Worker", "Active", None),
        ("U1005", "mgarcia", "Maria Garcia", "HR", "HR Specialist", "On Leave", None),
        ("U1006", "akapoor", "Arjun Kapoor", "Admissions", "Admissions Officer", "Active", None),
        ("U1007", "ssummers", "Sarah Summers", "Registrar", "Data Analyst", "Terminated", "2026-10-01"),
    ]

    cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", users)

    logs: List[Tuple] = [
        # --- Normal Baseline Activity ---
        ("U1001", "2026-10-10 09:15:22", "Active_Directory_Domain_Controller", "READ_CONFIG", "10.10.1.15", "Campus_HQ", "Success"),
        ("U1002", "2026-10-10 10:02:11", "Payroll_Admin_Portal", "EXPORT_LEDGER", "10.10.2.44", "Campus_Finance", "Success"),
        ("U1006", "2026-10-10 11:30:00", "Applicant_Portal", "VIEW_APPLICATION", "10.10.4.12", "Campus_Admissions", "Success"),
        ("U1004", "2026-10-10 14:20:05", "Library_Catalog_System", "CHECKOUT_BOOK", "10.10.8.99", "Campus_Library", "Success"),

        # --- ANOMALY 1: CTRL-01 Orphaned Account Activity (Post-Termination Access) ---
        ("U1003", "2026-10-11 22:14:09", "VPN_Gateway_Main", "LOGIN", "185.220.101.4", "External_TOR_Exit", "Success"),
        ("U1003", "2026-10-11 22:18:45", "Student_SSN_Registry", "BULK_DOWNLOAD", "185.220.101.4", "External_TOR_Exit", "Success"),
        ("U1007", "2026-10-12 08:45:00", "Financial_Aid_Master_DB", "QUERY_RECORDS", "192.168.1.50", "Remote_VPN", "Success"),

        # --- ANOMALY 2: CTRL-02 Segregation of Duties (SoD) / Unauthorized Privilege ---
        ("U1004", "2026-10-12 13:10:33", "Payroll_Admin_Portal", "MODIFY_SALARY", "10.10.8.99", "Campus_Library", "Success"),
        ("U1006", "2026-10-12 15:40:12", "Active_Directory_Domain_Controller", "GRANT_ADMIN", "10.10.4.12", "Campus_Admissions", "Success"),

        # --- ANOMALY 3: CTRL-03 Brute Force / Credential Stuffing Sequence ---
        ("U1002", "2026-10-13 01:05:01", "Financial_Aid_Master_DB", "LOGIN", "45.33.32.156", "External_Unknown", "Failed"),
        ("U1002", "2026-10-13 01:05:12", "Financial_Aid_Master_DB", "LOGIN", "45.33.32.156", "External_Unknown", "Failed"),
        ("U1002", "2026-10-13 01:05:25", "Financial_Aid_Master_DB", "LOGIN", "45.33.32.156", "External_Unknown", "Failed"),
        ("U1002", "2026-10-13 01:05:40", "Financial_Aid_Master_DB", "LOGIN", "45.33.32.156", "External_Unknown", "Failed"),
        ("U1002", "2026-10-13 01:06:02", "Financial_Aid_Master_DB", "EXPORT_ALL", "45.33.32.156", "External_Unknown", "Success"),

        # --- ANOMALY 4: CTRL-04 Off-Hours Sensitive Access (00:00 - 05:00) ---
        ("U1001", "2026-10-14 03:22:19", "Student_SSN_Registry", "SCHEMA_DUMP", "10.10.1.15", "Campus_HQ", "Success"),

        # --- ANOMALY 5: CTRL-05 Leave-of-Absence Account Activity ---
        ("U1005", "2026-10-14 16:45:10", "Payroll_Admin_Portal", "VIEW_TAX_FORMS", "172.16.0.88", "Remote_VPN", "Success"),
    ]

    cursor.executemany(
        """
        INSERT INTO access_logs 
        (user_id, timestamp, resource, action, ip_address, location, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        logs,
    )

    conn.commit()
