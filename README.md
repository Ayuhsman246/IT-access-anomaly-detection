# IT Access Anomaly Detection & ITGC Audit Engine

![Language](https://img.shields.io/badge/Language-Python_3.8%2B-blue.svg)
![Database](https://img.shields.io/badge/Database-SQLite3-lightgrey.svg)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero_(Standard_Library)-brightgreen.svg)
![Compliance](https://img.shields.io/badge/Compliance-SOX_404_%7C_SOC_2_%7C_ISO_27001-orange.svg)

## Executive Summary
In enterprise and higher-education IT ecosystems, identity and access governance failures represent a primary source of data breach exposure and regulatory compliance deficiencies. Ineffective deprovisioning, segregation-of-duties (SoD) bypasses, credential stuffing, and unmonitored off-hours activity frequently compromise core infrastructure while remaining undetectable through traditional manual sampling audits.

**`it-access-anomaly-detection`** is an automated Computer-Assisted Audit Technique (CAAT) and Identity & Access Management (IAM) analytics engine designed for **100% population testing**. Operating on standard Python libraries with zero external dependencies, it ingests identity master records and system authentication logs into an embedded relational SQLite datastore, executes deterministic SQL audit detection rules, prioritizes identified risk exposures by severity, and exports audit-ready evidence workpapers alongside an executive console summary.

---

## Key Audit Objectives & Regulatory Alignment
This audit engine automates core IT General Controls (ITGC) validation aligned with industry governance frameworks:

| Framework | Control Reference | Audit Area & Objective |
| :--- | :--- | :--- |
| **SOX Section 404** | ITGC Access Controls (AC) | Logical access security, timely termination deprovisioning, and authorization restrictions on financial reporting systems. |
| **SOC 2 Type II** | Trust Services Criteria CC6.1, CC6.2, CC6.3 | Logical boundary protection, role-based access control (RBAC) enforcement, and monitoring of credential compromise. |
| **NIST SP 800-53 Rev. 5** | AC-2 (Account Mgmt), AC-6 (Least Privilege), AU-6 (Audit Review) | Automated identification of orphaned/inactive accounts, unauthorized privilege use, and anomalous access behaviors. |
| **ISO/IEC 27001:2022** | Controls A.5.15, A.8.2, A.8.16 | Access control policy enforcement, privileged access rights management, and continuous log monitoring activities. |

---

## Modular Architecture
The solution is decoupled into focused, testable modules adhering to clean software engineering and single-responsibility principles:

```text
it-access-anomaly-detection/
├── main.py                       # CLI orchestrator and execution entrypoint
├── README.md                     # Executive portfolio & project documentation
├── src/
│   ├── __init__.py               # Package initializer
│   ├── config.py                 # Centralized configuration, paths, and audit thresholds
│   ├── database.py               # SQLite schema definition and synthetic telemetry seeder
│   ├── detector.py               # SQL-driven ITGC audit control detection rules
│   └── reporter.py               # Structured CSV report exporter and console summary formatter
└── results/                      # Auto-generated audit artifacts
    ├── campus_audit.db           # Relational SQLite database of simulated audit logs
    └── audit_findings_sample.csv # Prioritized IT audit findings and evidentiary descriptions
```

### Module Responsibilities

- **`main.py`**: CLI orchestrator. Establishes the database connection, invokes the synthetic telemetry seeder, triggers audit control evaluations, exports the findings workpaper, and prints the executive dashboard.
- **`src/__init__.py`**: Package marker exposing package docstrings and structure.
- **`src/config.py`**: Defines root path resolutions (`pathlib.Path`), output artifact destinations, sanitized terminal display constants (`results/campus_audit.db`, `results/audit_findings_sample.csv`), audit evaluation parameters (`OFF_HOURS_START = 0`, `OFF_HOURS_END = 4`, `BRUTE_FORCE_THRESHOLD = 4`), and designated sensitive resources.
- **`src/database.py`**: Manages SQLite table creation (`users`, `access_logs`) and populates realistic corporate employee personas alongside deterministic baseline and anomalous access events.
- **`src/detector.py`**: Implements parameterized SQL detection logic across controls CTRL-01 through CTRL-05, returning normalized audit finding objects.
- **`src/reporter.py`**: Generates the RFC 4180-compliant CSV audit workpaper and outputs the formatted executive summary table to terminal stdout.

---

## Audit Control Rules (Detection Logic)

### CTRL-01: Orphaned Account Activity (Post-Termination Access)
- **Severity**: `CRITICAL`
- **Objective**: Identify any authenticated activity performed by users flagged as Terminated in HR master records or occurring after their recorded termination date.
- **Threat Vector**: Unrevoked contractor credentials, insider threat, post-employment data exfiltration.
- **Evaluation Logic**:
  ```sql
  SELECT u.user_id, u.username, u.department, u.role, u.termination_date,
         l.resource, l.action, l.timestamp, l.ip_address
  FROM access_logs l
  JOIN users u ON l.user_id = u.user_id
  WHERE u.status = 'Terminated'
  ```

---

### CTRL-02: Segregation of Duties (SoD) & Privilege Creep
- **Severity**: `HIGH`
- **Objective**: Detect non-privileged or unauthorized roles (e.g., student workers, non-IT personnel) accessing sensitive repositories (Active_Directory_Domain_Controller, Payroll_Admin_Portal, Financial_Aid_Master_DB).
- **Threat Vector**: Unauthorized vertical/horizontal privilege escalation, fraudulent payroll modification.
- **Evaluation Logic**:
  ```sql
  SELECT u.user_id, u.username, u.department, u.role,
         l.resource, l.action, l.timestamp, l.ip_address
  FROM access_logs l
  JOIN users u ON l.user_id = u.user_id
  WHERE l.resource IN ('Financial_Aid_Master_DB', 'Payroll_Admin_Portal', 'Student_SSN_Registry', 'Active_Directory_Domain_Controller')
    AND u.role NOT IN ('SysAdmin', 'Senior Accountant', 'HR Specialist')
    AND u.status = 'Active'
  ```

---

### CTRL-03: Brute Force / Credential Compromise Sequence
- **Severity**: `HIGH`
- **Objective**: Flag credential stuffing or brute-force attacks characterized by 4 or more failed login attempts from a single IP/account cluster followed by a successful session.
- **Threat Vector**: Automated password spraying, credential stuffing, account takeover (ATO).
- **Evaluation Logic**:
  ```sql
  SELECT u.user_id, u.username, u.department, u.role,
         l.resource, MAX(l.timestamp) as latest_timestamp, l.ip_address,
         SUM(CASE WHEN l.status = 'Failed' THEN 1 ELSE 0 END) as failed_count,
         SUM(CASE WHEN l.status = 'Success' THEN 1 ELSE 0 END) as success_count
  FROM access_logs l
  JOIN users u ON l.user_id = u.user_id
  GROUP BY u.user_id, l.ip_address, l.resource
  HAVING failed_count >= 4
  ```

---

### CTRL-04: After-Hours Sensitive Asset Access
- **Severity**: `MEDIUM`
- **Objective**: Monitor successful operations on critical data repositories executed outside standard business windows (00:00 to 05:00 local time).
- **Threat Vector**: Covert data exfiltration during low-SOC-staffing windows, unauthorized database dumping.
- **Evaluation Logic**:
  ```sql
  SELECT u.user_id, u.username, u.department, u.role,
         l.resource, l.action, l.timestamp, l.ip_address
  FROM access_logs l
  JOIN users u ON l.user_id = u.user_id
  WHERE l.resource IN ('Financial_Aid_Master_DB', 'Payroll_Admin_Portal', 'Student_SSN_Registry', 'Active_Directory_Domain_Controller')
    AND l.status = 'Success'
    AND CAST(strftime('%H', l.timestamp) AS INTEGER) BETWEEN 0 AND 4
    AND u.status = 'Active'
  ```

---

### CTRL-05: Dormant / On-Leave Account Usage
- **Severity**: `MEDIUM`
- **Objective**: Flag any active authentication or data access performed by employees currently listed on HR Leave of Absence (On Leave).
- **Threat Vector**: Credential sharing, unauthorized off-duty system alteration.
- **Evaluation Logic**:
  ```sql
  SELECT u.user_id, u.username, u.department, u.role,
         l.resource, l.action, l.timestamp, l.ip_address
  FROM access_logs l
  JOIN users u ON l.user_id = u.user_id
  WHERE u.status = 'On Leave'
  ```

---

## Execution Verification & Terminal Output

Run the audit pipeline from the project root:

```bash
python main.py
```

### Console Executive Summary (stdout)

```plaintext
========================================================================================
  IT ACCESS ANOMALY DETECTION & ITGC AUDIT ENGINE
========================================================================================
  [+] Database Generated : results/campus_audit.db
  [+] CSV Report Exported: results/audit_findings_sample.csv
  [+] Scope Analyzed     : 7 User Identities | 16 Access Events
----------------------------------------------------------------------------------------
  SUMMARY BY SEVERITY    : CRITICAL: 3 | HIGH: 3 | MEDIUM: 3 | TOTAL FINDINGS: 9
========================================================================================
ID       CTRL     SEVERITY   USER       RESOURCE                           TIMESTAMP          
----------------------------------------------------------------------------------------
FND-001  CTRL-01  CRITICAL   rmiller    VPN_Gateway_Main                   2026-10-11 22:14:09
FND-002  CTRL-01  CRITICAL   rmiller    Student_SSN_Registry               2026-10-11 22:18:45
FND-003  CTRL-01  CRITICAL   ssummers   Financial_Aid_Master_DB            2026-10-12 08:45:00
FND-004  CTRL-02  HIGH       tchen      Payroll_Admin_Portal               2026-10-12 13:10:33
FND-005  CTRL-02  HIGH       akapoor    Active_Directory_Domain_Control... 2026-10-12 15:40:12
FND-006  CTRL-03  HIGH       asmith     Financial_Aid_Master_DB            2026-10-13 01:06:02
FND-007  CTRL-04  MEDIUM     asmith     Financial_Aid_Master_DB            2026-10-13 01:06:02
FND-008  CTRL-04  MEDIUM     jdoe       Student_SSN_Registry               2026-10-14 03:22:19
FND-009  CTRL-05  MEDIUM     mgarcia    Payroll_Admin_Portal               2026-10-14 16:45:10
========================================================================================
```

### Generated Audit Workpaper (`results/audit_findings_sample.csv`)

```csv
finding_id,control_id,control_name,severity,user_id,username,department,role,resource,timestamp,ip_address,evidence_description
FND-001,CTRL-01,Orphaned Account Activity,CRITICAL,U1003,rmiller,Facilities,Contractor,VPN_Gateway_Main,2026-10-11 22:14:09,185.220.101.4,"Terminated user (Term Date: 2026-09-15) executed 'LOGIN' on VPN_Gateway_Main."
FND-002,CTRL-01,Orphaned Account Activity,CRITICAL,U1003,rmiller,Facilities,Contractor,Student_SSN_Registry,2026-10-11 22:18:45,185.220.101.4,"Terminated user (Term Date: 2026-09-15) executed 'BULK_DOWNLOAD' on Student_SSN_Registry."
FND-003,CTRL-01,Orphaned Account Activity,CRITICAL,U1007,ssummers,Registrar,Data Analyst,Financial_Aid_Master_DB,2026-10-12 08:45:00,192.168.1.50,"Terminated user (Term Date: 2026-10-01) executed 'QUERY_RECORDS' on Financial_Aid_Master_DB."
FND-004,CTRL-02,Segregation of Duties Violation,HIGH,U1004,tchen,Library,Student Worker,Payroll_Admin_Portal,2026-10-12 13:10:33,10.10.8.99,"Unauthorized role 'Student Worker' (Library) performed privileged action 'MODIFY_SALARY' on Payroll_Admin_Portal."
FND-005,CTRL-02,Segregation of Duties Violation,HIGH,U1006,akapoor,Admissions,Admissions Officer,Active_Directory_Domain_Controller,2026-10-12 15:40:12,10.10.4.12,"Unauthorized role 'Admissions Officer' (Admissions) performed privileged action 'GRANT_ADMIN' on Active_Directory_Domain_Controller."
FND-006,CTRL-03,Brute Force / Credential Compromise,HIGH,U1002,asmith,Finance,Senior Accountant,Financial_Aid_Master_DB,2026-10-13 01:06:02,45.33.32.156,"Detected 4 failed logins followed by 1 successful access event(s) from IP 45.33.32.156."
FND-007,CTRL-04,After-Hours Sensitive Access,MEDIUM,U1002,asmith,Finance,Senior Accountant,Financial_Aid_Master_DB,2026-10-13 01:06:02,45.33.32.156,"Off-hours execution of 'EXPORT_ALL' on sensitive asset Financial_Aid_Master_DB at 2026-10-13 01:06:02."
FND-008,CTRL-04,After-Hours Sensitive Access,MEDIUM,U1001,jdoe,IT Security,SysAdmin,Student_SSN_Registry,2026-10-14 03:22:19,10.10.1.15,"Off-hours execution of 'SCHEMA_DUMP' on sensitive asset Student_SSN_Registry at 2026-10-14 03:22:19."
FND-009,CTRL-05,Dormant / On-Leave Account Usage,MEDIUM,U1005,mgarcia,HR,HR Specialist,Payroll_Admin_Portal,2026-10-14 16:45:10,172.16.0.88,"User with HR status 'On Leave' performed 'VIEW_TAX_FORMS' on Payroll_Admin_Portal."
```

---

## Future Enhancements

1. **Import Real CSV Files:** Update the script to read user and access logs directly from standard `.csv` or Excel files instead of using sample data inside the code.
2. **Inactive Account Check (90+ Days):** Add a simple check to flag active user accounts that have not logged into the system for more than 90 days.
