"""Comprehensive unit test suite for Station 2: Hayabusa Integration and AST CLI Normalization."""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from config import PipelineConfig
from mock_generator import MOCK_EVENTS, SCHEMA_SQL
from station2_hayabusa import (
    WEIGHT_MAP,
    SigmaAlertAggregate,
    enrich_sqlite_database,
    execute_station2,
    normalize_severity,
    normalize_windows_cli,
    parse_hayabusa_jsonl,
    run_hayabusa,
)


class TestStation2Hayabusa(unittest.TestCase):
    """Test suite covering all 24 required Station 2 criteria."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_trace.db")
        self.jsonl_path = os.path.join(self.test_dir, "test_alerts.jsonl")

        # Initialize mock database
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.executescript(SCHEMA_SQL)
        cols = list(MOCK_EVENTS[0].keys())
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO events ({', '.join(cols)}) VALUES ({placeholders})"
        for ev in MOCK_EVENTS:
            cur.execute(sql, [ev[c] for c in cols])
        conn.commit()
        conn.close()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Valid JSONL parsing
    def test_01_valid_jsonl_parsing(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "EventRecordID": 1,
                "RuleID": "sigma-001",
                "RuleTitle": "Suspicious PowerShell",
                "Level": "high",
                "Tactics": ["execution"],
            }) + "\n")

        aggregates, valid, malformed, field_name = parse_hayabusa_jsonl(self.jsonl_path)
        self.assertEqual(valid, 1)
        self.assertEqual(malformed, 0)
        self.assertIn(1, aggregates)
        self.assertEqual(aggregates[1].max_rule_id, "sigma-001")

    # 2. Multiple JSONL lines
    def test_02_multiple_jsonl_lines(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Level": "low"}) + "\n")
            f.write(json.dumps({"EventRecordID": 2, "Level": "medium"}) + "\n")
            f.write(json.dumps({"EventRecordID": 3, "Level": "high"}) + "\n")

        aggregates, valid, malformed, _ = parse_hayabusa_jsonl(self.jsonl_path)
        self.assertEqual(valid, 3)
        self.assertEqual(len(aggregates), 3)

    # 3. Malformed JSONL handling
    def test_03_malformed_jsonl_handling(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write("NOT_A_VALID_JSON\n")
            f.write(json.dumps({"EventRecordID": 1, "Level": "low"}) + "\n")
            f.write("{corrupt_json: true\n")

        aggregates, valid, malformed, _ = parse_hayabusa_jsonl(self.jsonl_path)
        self.assertEqual(valid, 1)
        self.assertEqual(malformed, 2)
        self.assertIn(1, aggregates)

    # 4. Missing EventRecordID handling
    def test_04_missing_event_record_id(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"RuleID": "sigma-no-id", "Level": "high"}) + "\n")
            f.write(json.dumps({"EventRecordID": "invalid_int", "Level": "high"}) + "\n")
            f.write(json.dumps({"EventRecordID": 4, "Level": "high"}) + "\n")

        aggregates, valid, malformed, _ = parse_hayabusa_jsonl(self.jsonl_path)
        self.assertEqual(valid, 1)
        self.assertEqual(len(aggregates), 1)
        self.assertIn(4, aggregates)

    # 5. Exact EventRecordID extraction
    def test_05_exact_event_record_id_extraction(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 42, "Level": "critical"}) + "\n")

        aggregates, _, _, field_name = parse_hayabusa_jsonl(self.jsonl_path)
        self.assertEqual(field_name, "EventRecordID")
        self.assertIn(42, aggregates)

    # 6. Exact record_index matching
    def test_06_exact_record_index_matching(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 2, "RuleID": "rule-2", "Level": "critical"}) + "\n")

        execute_station2(self.db_path, self.jsonl_path)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT max_sigma_rule_id, sigma_weight FROM events WHERE record_index = 2")
        row = cur.fetchone()
        conn.close()
        self.assertEqual(row[0], "rule-2")
        self.assertEqual(row[1], 1.0)

    # 7. Unmatched EventRecordID handling
    def test_07_unmatched_event_record_id_handling(self):
        # Alert for EventRecordID 999 which does not exist in mock DB
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 999, "RuleID": "phantom", "Level": "critical"}) + "\n")

        results = execute_station2(self.db_path, self.jsonl_path)
        self.assertEqual(results["matched_sigma_records"], 0)
        self.assertEqual(results["unmatched_sigma_records"], 6)

    # 8. Sigma severity normalization
    def test_08_severity_normalization(self):
        self.assertEqual(normalize_severity("critical"), ("critical", 1.0))
        self.assertEqual(normalize_severity("HIGH"), ("high", 0.9))
        self.assertEqual(normalize_severity("  Medium  "), ("medium", 0.6))
        self.assertEqual(normalize_severity("Low"), ("low", 0.3))
        self.assertEqual(normalize_severity("informational"), ("informational", 0.1))
        self.assertEqual(normalize_severity("none"), ("none", 0.0))
        self.assertEqual(normalize_severity("unknown_level"), ("none", 0.0))
        self.assertEqual(normalize_severity(None), ("none", 0.0))

    # 9. info alias handling
    def test_09_info_alias_handling(self):
        self.assertEqual(normalize_severity("info"), ("informational", 0.1))
        self.assertEqual(normalize_severity("  INFO  "), ("informational", 0.1))

    # 10. Highest-weight alert selection
    def test_10_highest_weight_alert_selection(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "RuleID": "rule-low", "Level": "low"}) + "\n")
            f.write(json.dumps({"EventRecordID": 1, "RuleID": "rule-crit", "Level": "critical"}) + "\n")
            f.write(json.dumps({"EventRecordID": 1, "RuleID": "rule-med", "Level": "medium"}) + "\n")

        aggregates, _, _, _ = parse_hayabusa_jsonl(self.jsonl_path)
        self.assertEqual(aggregates[1].max_rule_id, "rule-crit")
        self.assertEqual(aggregates[1].max_weight, 1.0)

    # 11. Deterministic equal-weight handling
    def test_11_deterministic_equal_weight_handling(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "RuleID": "rule-B", "Level": "high"}) + "\n")
            f.write(json.dumps({"EventRecordID": 1, "RuleID": "rule-A", "Level": "high"}) + "\n")

        aggregates, _, _, _ = parse_hayabusa_jsonl(self.jsonl_path)
        # Lexicographically smaller RuleID ("rule-A") wins tie-break
        self.assertEqual(aggregates[1].max_rule_id, "rule-A")

    # 12. MITRE tactic merging and deduplication
    def test_12_mitre_tactic_merging(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Tactics": ["execution", "persistence"]}) + "\n")
            f.write(json.dumps({"EventRecordID": 1, "Tactics": ["persistence", "defense-evasion"]}) + "\n")

        aggregates, _, _, _ = parse_hayabusa_jsonl(self.jsonl_path)
        expected = ["defense-evasion", "execution", "persistence"]
        self.assertEqual(aggregates[1].tactics, expected)

    # 13. CMD caret normalization
    def test_13_cmd_caret_normalization(self):
        raw = "w^h^o^a^m^i"
        self.assertEqual(normalize_windows_cli(raw), "whoami")

    # 14. Dummy quote normalization
    def test_14_dummy_quote_normalization(self):
        self.assertEqual(normalize_windows_cli('w""hoami'), "whoami")
        self.assertEqual(normalize_windows_cli('pow""ershell'), "powershell")

    # 15. PowerShell backtick normalization
    def test_15_powershell_backtick_normalization(self):
        self.assertEqual(normalize_windows_cli("i`e`x"), "iex")

    # 16. UTF-16LE Base64 decoding
    def test_16_utf16le_base64_decoding(self):
        # SQBFAFgA is UTF-16LE Base64 for IEX
        raw = "powershell.exe -enc SQBFAFgA"
        normalized = normalize_windows_cli(raw)
        self.assertIn("[DECODED_B64: IEX]", normalized)

    # 17. Malformed Base64 preservation
    def test_17_malformed_base64_preservation(self):
        raw = "powershell.exe -enc NOT_VALID_B64!@#$"
        normalized = normalize_windows_cli(raw)
        self.assertEqual(normalized, raw)

    # 18. Empty and NULL command-line handling
    def test_18_empty_and_null_cli(self):
        self.assertIsNone(normalize_windows_cli(None))
        self.assertEqual(normalize_windows_cli(""), "")

    # 19. AST flag disabled behavior
    def test_19_ast_flag_disabled_behavior(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Level": "high"}) + "\n")

        cfg = PipelineConfig(use_ast_norm=False)
        execute_station2(self.db_path, self.jsonl_path, cfg)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT canonical_command_line FROM events WHERE record_index = 1")
        val = cur.fetchone()[0]
        conn.close()
        self.assertIsNone(val)

    # 20. Raw command-line preservation
    def test_20_raw_cli_preservation(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Level": "high"}) + "\n")

        cfg = PipelineConfig(use_ast_norm=True)
        execute_station2(self.db_path, self.jsonl_path, cfg)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT command_line, canonical_command_line FROM events WHERE record_index = 1")
        raw, canonical = cur.fetchone()
        conn.close()

        # Raw command line must be completely untouched
        self.assertEqual(raw, "powershell.exe -enc SQBFAFgA")
        # Canonical command line must hold the normalized representation
        self.assertIn("[DECODED_B64: IEX]", canonical)

    # 21. Exact SQLite schema preservation
    def test_21_exact_schema_preservation(self):
        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Level": "high"}) + "\n")

        execute_station2(self.db_path, self.jsonl_path)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(events)")
        cols = [r[1] for r in cur.fetchall()]
        conn.close()
        self.assertEqual(len(cols), 24)

    # 22. Raw forensic integrity field preservation
    def test_22_raw_forensic_integrity_preservation(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT raw_xml, raw_event_hash, chain_hash, raw_event_pointer FROM events WHERE record_index = 1")
        before = cur.fetchone()
        conn.close()

        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Level": "high"}) + "\n")

        execute_station2(self.db_path, self.jsonl_path)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT raw_xml, raw_event_hash, chain_hash, raw_event_pointer FROM events WHERE record_index = 1")
        after = cur.fetchone()
        conn.close()

        self.assertEqual(before, after)

    # 23. Ground-truth isolation
    def test_23_ground_truth_isolation(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT is_malicious_gt FROM events WHERE record_index = 1")
        before_gt = cur.fetchone()[0]
        conn.close()

        with open(self.jsonl_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"EventRecordID": 1, "Level": "high"}) + "\n")

        execute_station2(self.db_path, self.jsonl_path)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT is_malicious_gt FROM events WHERE record_index = 1")
        after_gt = cur.fetchone()[0]
        conn.close()

        self.assertEqual(before_gt, after_gt)

    # 24. Safe subprocess error handling
    def test_24_safe_subprocess_error_handling(self):
        with self.assertRaises(FileNotFoundError):
            run_hayabusa("non_existent_hayabusa.exe", "fake.evtx", "fake.jsonl")


if __name__ == "__main__":
    unittest.main()

