"""Mock Trace Generator for Pipeline Testing.

Populates:
- data/sqlite_db/mock_trace.db (using frozen 24-column SQLite schema)
- data/hayabusa_out/mock_hayabusa.jsonl (sample Hayabusa Sigma detection alerts)
"""

import json
import os
import sqlite3
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    record_index INTEGER PRIMARY KEY,
    eid TEXT UNIQUE,
    host TEXT,
    timestamp_utc TEXT,
    sysmon_event_id INTEGER,
    actor_guid TEXT,
    actor_process TEXT,
    action_type TEXT,
    target_guid TEXT,
    target_entity TEXT,
    command_line TEXT,
    canonical_command_line TEXT,
    logon_guid TEXT,
    user TEXT,
    raw_event_pointer TEXT,
    raw_event_hash TEXT,
    chain_hash TEXT,
    raw_xml TEXT,
    max_sigma_rule_id TEXT DEFAULT NULL,
    max_sigma_title TEXT DEFAULT NULL,
    max_sigma_level TEXT DEFAULT 'none',
    sigma_weight REAL DEFAULT 0.0,
    mitre_tactics TEXT DEFAULT NULL,
    is_malicious_gt INTEGER DEFAULT 0
);
"""

# Core synthetic fixtures (6 records): Process creation, file drop, registry persistence, execution
MOCK_EVENTS = [
    {
        "record_index": 1,
        "eid": "rec_1",
        "host": "WIN-FORENSIC-01",
        "timestamp_utc": "2026-11-09T10:00:00Z",
        "sysmon_event_id": 1,
        "actor_guid": "{00000000-0000-0000-0000-000000000001}",
        "actor_process": "C:\\Windows\\System32\\cmd.exe",
        "action_type": "PROCESS_CREATE",
        "target_guid": "{00000000-0000-0000-0000-000000000002}",
        "target_entity": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
        "canonical_command_line": None,
        "logon_guid": "{00000000-0000-0000-0000-0000000000AA}",
        "user": "NT AUTHORITY\\SYSTEM",
        "raw_event_pointer": "chunk_0_offset_100",
        "raw_event_hash": "a1b2c3d4e5f60101010101010101010101010101010101010101010101010101",
        "chain_hash": "c1c1c1c1c1c10101010101010101010101010101010101010101010101010101",
        "raw_xml": "<Event><System><EventRecordID>1</EventRecordID></System></Event>",
        "max_sigma_rule_id": "sigma-001",
        "max_sigma_title": "Suspicious PowerShell Encoded Command",
        "max_sigma_level": "high",
        "sigma_weight": 0.9,
        "mitre_tactics": json.dumps(["execution", "defense-evasion"]),
        "is_malicious_gt": 1,
    },
    {
        "record_index": 2,
        "eid": "rec_2",
        "host": "WIN-FORENSIC-01",
        "timestamp_utc": "2026-11-09T10:01:00Z",
        "sysmon_event_id": 11,
        "actor_guid": "{00000000-0000-0000-0000-000000000002}",
        "actor_process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "action_type": "FILE_CREATE",
        "target_guid": None,
        "target_entity": "C:\\Users\\Public\\malware.exe",
        "command_line": None,
        "canonical_command_line": None,
        "logon_guid": "{00000000-0000-0000-0000-0000000000AA}",
        "user": "NT AUTHORITY\\SYSTEM",
        "raw_event_pointer": "chunk_0_offset_200",
        "raw_event_hash": "a1b2c3d4e5f60202020202020202020202020202020202020202020202020202",
        "chain_hash": "c2c2c2c2c2c20202020202020202020202020202020202020202020202020202",
        "raw_xml": "<Event><System><EventRecordID>2</EventRecordID></System></Event>",
        "max_sigma_rule_id": "sigma-002",
        "max_sigma_title": "Executable Drop in Public Directory",
        "max_sigma_level": "medium",
        "sigma_weight": 0.6,
        "mitre_tactics": json.dumps(["persistence"]),
        "is_malicious_gt": 1,
    },
    {
        "record_index": 3,
        "eid": "rec_3",
        "host": "WIN-FORENSIC-01",
        "timestamp_utc": "2026-11-09T10:02:00Z",
        "sysmon_event_id": 13,
        "actor_guid": "{00000000-0000-0000-0000-000000000002}",
        "actor_process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "action_type": "REGISTRY_EVENT",
        "target_guid": None,
        "target_entity": "C:\\Users\\Public\\malware.exe",
        "command_line": None,
        "canonical_command_line": None,
        "logon_guid": "{00000000-0000-0000-0000-0000000000AA}",
        "user": "NT AUTHORITY\\SYSTEM",
        "raw_event_pointer": "chunk_0_offset_300",
        "raw_event_hash": "a1b2c3d4e5f60303030303030303030303030303030303030303030303030303",
        "chain_hash": "c3c3c3c3c3c30303030303030303030303030303030303030303030303030303",
        "raw_xml": "<Event><System><EventRecordID>3</EventRecordID></System></Event>",
        "max_sigma_rule_id": "sigma-003",
        "max_sigma_title": "Run Key Modification for Persistence",
        "max_sigma_level": "critical",
        "sigma_weight": 1.0,
        "mitre_tactics": json.dumps(["persistence"]),
        "is_malicious_gt": 1,
    },
    {
        "record_index": 4,
        "eid": "rec_4",
        "host": "WIN-FORENSIC-01",
        "timestamp_utc": "2026-11-09T10:03:00Z",
        "sysmon_event_id": 1,
        "actor_guid": "{00000000-0000-0000-0000-000000000002}",
        "actor_process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "action_type": "PROCESS_CREATE",
        "target_guid": "{00000000-0000-0000-0000-000000000003}",
        "target_entity": "C:\\Users\\Public\\malware.exe",
        "command_line": "C:\\Users\\Public\\malware.exe --run",
        "canonical_command_line": None,
        "logon_guid": "{00000000-0000-0000-0000-0000000000AA}",
        "user": "NT AUTHORITY\\SYSTEM",
        "raw_event_pointer": "chunk_0_offset_400",
        "raw_event_hash": "a1b2c3d4e5f60404040404040404040404040404040404040404040404040404",
        "chain_hash": "c4c4c4c4c4c40404040404040404040404040404040404040404040404040404",
        "raw_xml": "<Event><System><EventRecordID>4</EventRecordID></System></Event>",
        "max_sigma_rule_id": "sigma-004",
        "max_sigma_title": "Suspicious Binary Execution from Public Folder",
        "max_sigma_level": "high",
        "sigma_weight": 0.9,
        "mitre_tactics": json.dumps(["execution"]),
        "is_malicious_gt": 1,
    },
    {
        "record_index": 5,
        "eid": "rec_5",
        "host": "WIN-FORENSIC-01",
        "timestamp_utc": "2026-11-09T10:04:00Z",
        "sysmon_event_id": 1,
        "actor_guid": "{00000000-0000-0000-0000-000000000099}",
        "actor_process": "C:\\Windows\\System32\\services.exe",
        "action_type": "PROCESS_CREATE",
        "target_guid": "{00000000-0000-0000-0000-000000000098}",
        "target_entity": "C:\\Windows\\System32\\svchost.exe",
        "command_line": "svchost.exe -k LocalService",
        "canonical_command_line": None,
        "logon_guid": "{00000000-0000-0000-0000-0000000000AA}",
        "user": "NT AUTHORITY\\SYSTEM",
        "raw_event_pointer": "chunk_0_offset_500",
        "raw_event_hash": "a1b2c3d4e5f60505050505050505050505050505050505050505050505050505",
        "chain_hash": "c5c5c5c5c5c50505050505050505050505050505050505050505050505050505",
        "raw_xml": "<Event><System><EventRecordID>5</EventRecordID></System></Event>",
        "max_sigma_rule_id": None,
        "max_sigma_title": None,
        "max_sigma_level": "none",
        "sigma_weight": 0.0,
        "mitre_tactics": None,
        "is_malicious_gt": 0,
    },
    {
        "record_index": 6,
        "eid": "rec_6",
        "host": "WIN-FORENSIC-01",
        "timestamp_utc": "2026-11-09T10:05:00Z",
        "sysmon_event_id": 1,
        "actor_guid": "{00000000-0000-0000-0000-000000000098}",
        "actor_process": "C:\\Windows\\System32\\svchost.exe",
        "action_type": "PROCESS_CREATE",
        "target_guid": "{00000000-0000-0000-0000-000000000097}",
        "target_entity": "C:\\Windows\\System32\\RuntimeBroker.exe",
        "command_line": "RuntimeBroker.exe -Embedding",
        "canonical_command_line": None,
        "logon_guid": "{00000000-0000-0000-0000-0000000000AA}",
        "user": "NT AUTHORITY\\SYSTEM",
        "raw_event_pointer": "chunk_0_offset_600",
        "raw_event_hash": "a1b2c3d4e5f60606060606060606060606060606060606060606060606060606",
        "chain_hash": "c6c6c6c6c6c60606060606060606060606060606060606060606060606060606",
        "raw_xml": "<Event><System><EventRecordID>6</EventRecordID></System></Event>",
        "max_sigma_rule_id": None,
        "max_sigma_title": None,
        "max_sigma_level": "none",
        "sigma_weight": 0.0,
        "mitre_tactics": None,
        "is_malicious_gt": 0,
    },
]

MOCK_HAYABUSA_JSONL = [
    {
        "EventRecordID": 1,
        "RuleID": "sigma-001",
        "RuleTitle": "Suspicious PowerShell Encoded Command",
        "Level": "high",
        "Tactics": ["execution", "defense-evasion"],
    },
    {
        "EventRecordID": 2,
        "RuleID": "sigma-002",
        "RuleTitle": "Executable Drop in Public Directory",
        "Level": "medium",
        "Tactics": ["persistence"],
    },
    {
        "EventRecordID": 3,
        "RuleID": "sigma-003",
        "RuleTitle": "Run Key Modification for Persistence",
        "Level": "critical",
        "Tactics": ["persistence"],
    },
    {
        "EventRecordID": 4,
        "RuleID": "sigma-004",
        "RuleTitle": "Suspicious Binary Execution from Public Folder",
        "Level": "high",
        "Tactics": ["execution"],
    },
]


def generate_mock_database(db_path: str = "data/sqlite_db/mock_trace.db") -> None:
    """Creates and populates the mock SQLite database."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)

    cols = list(MOCK_EVENTS[0].keys())
    placeholders = ", ".join(["?"] * len(cols))
    sql = f"INSERT OR REPLACE INTO events ({', '.join(cols)}) VALUES ({placeholders})"

    for ev in MOCK_EVENTS:
        values = [ev[c] for c in cols]
        cur.execute(sql, values)

    conn.commit()
    conn.close()


def generate_mock_hayabusa(jsonl_path: str = "data/hayabusa_out/mock_hayabusa.jsonl") -> None:
    """Generates the mock Hayabusa JSONL alert file."""
    os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for entry in MOCK_HAYABUSA_JSONL:
            f.write(json.dumps(entry) + "\n")


def generate_all() -> None:
    """Runs all mock generation routines."""
    generate_mock_database()
    generate_mock_hayabusa()


if __name__ == "__main__":
    generate_all()
    print("Mock trace database and Hayabusa JSONL alerts generated successfully.")

