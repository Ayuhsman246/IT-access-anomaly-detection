import sqlite3
from typing import Dict, List, Any
from src.config import SENSITIVE_RESOURCES, BRUTE_FORCE_THRESHOLD, OFF_HOURS_START, OFF_HOURS_END


def run_all_audit_controls(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Executes all ITGC anomaly detection queries and returns standardized audit findings."""
    conn.row_factory = sqlite3.Row
    findings: List[Dict[str, Any]] = []

    findings.extend(_detect_orphaned_accounts(conn))
    findings.extend(_detect_sod_violations(conn))
    findings.extend(_detect_brute_force(conn))
    findings.extend(_detect_off_hours_access(conn))
    findings.extend(_detect_on_leave_activity(conn))

    for idx, item in enumerate(findings, start=1):
        item["finding_id"] = f"FND-{idx:03d}"

    return findings


def _detect_orphaned_accounts(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    query = """
        SELECT u.user_id, u.username, u.department, u.role, u.termination_date,
               l.resource, l.action, l.timestamp, l.ip_address
        FROM access_logs l
        JOIN users u ON l.user_id = u.user_id
        WHERE u.status = 'Terminated'
    """
    rows = conn.execute(query).fetchall()
    return [
        {
            "control_id": "CTRL-01",
            "control_name": "Orphaned Account Activity",
            "severity": "CRITICAL",
            "user_id": r["user_id"],
            "username": r["username"],
            "department": r["department"],
            "role": r["role"],
            "resource": r["resource"],
            "timestamp": r["timestamp"],
            "ip_address": r["ip_address"],
            "evidence_description": (
                f"Terminated user (Term Date: {r['termination_date']}) executed "
                f"'{r['action']}' on {r['resource']}."
            ),
        }
        for r in rows
    ]


def _detect_sod_violations(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    placeholders = ",".join("?" for _ in SENSITIVE_RESOURCES)
    query = f"""
        SELECT u.user_id, u.username, u.department, u.role,
               l.resource, l.action, l.timestamp, l.ip_address
        FROM access_logs l
        JOIN users u ON l.user_id = u.user_id
        WHERE l.resource IN ({placeholders})
          AND u.role NOT IN ('SysAdmin', 'Senior Accountant', 'HR Specialist')
          AND u.status = 'Active'
    """
    rows = conn.execute(query, SENSITIVE_RESOURCES).fetchall()
    return [
        {
            "control_id": "CTRL-02",
            "control_name": "Segregation of Duties Violation",
            "severity": "HIGH",
            "user_id": r["user_id"],
            "username": r["username"],
            "department": r["department"],
            "role": r["role"],
            "resource": r["resource"],
            "timestamp": r["timestamp"],
            "ip_address": r["ip_address"],
            "evidence_description": (
                f"Unauthorized role '{r['role']}' ({r['department']}) performed "
                f"privileged action '{r['action']}' on {r['resource']}."
            ),
        }
        for r in rows
    ]


def _detect_brute_force(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    query = """
        SELECT u.user_id, u.username, u.department, u.role,
               l.resource, MAX(l.timestamp) as latest_timestamp, l.ip_address,
               SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) as failed_count,
               SUM(CASE WHEN l.status = 'Success' THEN 1 ELSE 0 END) as success_count
        FROM access_logs l
        JOIN users u ON l.user_id = u.user_id
        GROUP BY u.user_id, l.ip_address, l.resource
        HAVING failed_count >= ?
    """
    rows = conn.execute(query, (BRUTE_FORCE_THRESHOLD,)).fetchall()
    return [
        {
            "control_id": "CTRL-03",
            "control_name": "Brute Force / Credential Compromise",
            "severity": "HIGH",
            "user_id": r["user_id"],
            "username": r["username"],
            "department": r["department"],
            "role": r["role"],
            "resource": r["resource"],
            "timestamp": r["latest_timestamp"],
            "ip_address": r["ip_address"],
            "evidence_description": (
                f"Detected {r['failed_count']} failed logins followed by "
                f"{r['success_count']} successful access event(s) from IP {r['ip_address']}."
            ),
        }
        for r in rows
    ]


def _detect_off_hours_access(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    placeholders = ",".join("?" for _ in SENSITIVE_RESOURCES)
    query = f"""
        SELECT u.user_id, u.username, u.department, u.role,
               l.resource, l.action, l.timestamp, l.ip_address
        FROM access_logs l
        JOIN users u ON l.user_id = u.user_id
        WHERE l.resource IN ({placeholders})
          AND l.status = 'Success'
          AND CAST(strftime('%H', l.timestamp) AS INTEGER) BETWEEN ? AND ?
          AND u.status = 'Active'
    """
    params = (*SENSITIVE_RESOURCES, OFF_HOURS_START, OFF_HOURS_END)
    rows = conn.execute(query, params).fetchall()
    return [
        {
            "control_id": "CTRL-04",
            "control_name": "After-Hours Sensitive Access",
            "severity": "MEDIUM",
            "user_id": r["user_id"],
            "username": r["username"],
            "department": r["department"],
            "role": r["role"],
            "resource": r["resource"],
            "timestamp": r["timestamp"],
            "ip_address": r["ip_address"],
            "evidence_description": (
                f"Off-hours execution of '{r['action']}' on sensitive asset "
                f"{r['resource']} at {r['timestamp']}."
            ),
        }
        for r in rows
    ]


def _detect_on_leave_activity(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    query = """
        SELECT u.user_id, u.username, u.department, u.role,
               l.resource, l.action, l.timestamp, l.ip_address
        FROM access_logs l
        JOIN users u ON l.user_id = u.user_id
        WHERE u.status = 'On Leave'
    """
    rows = conn.execute(query).fetchall()
    return [
        {
            "control_id": "CTRL-05",
            "control_name": "Dormant / On-Leave Account Usage",
            "severity": "MEDIUM",
            "user_id": r["user_id"],
            "username": r["username"],
            "department": r["department"],
            "role": r["role"],
            "resource": r["resource"],
            "timestamp": r["timestamp"],
            "ip_address": r["ip_address"],
            "evidence_description": (
                f"User with HR status 'On Leave' performed '{r['action']}' "
                f"on {r['resource']}."
            ),
        }
        for r in rows
    ]
