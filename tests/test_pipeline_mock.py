"""Initial pipeline test suite validating configuration, schema contracts, and mock generator."""

import json
import sqlite3
import unittest
from pathlib import Path

from config import PipelineConfig, config
from mock_generator import MOCK_EVENTS, SCHEMA_SQL, generate_all


class TestPipelineFoundation(unittest.TestCase):
    """Foundation test suite for TEAM T12 DFIR pipeline."""

    def test_pipeline_config_defaults(self):
        """Verifies PipelineConfig dataclass fields and default values."""
        self.assertFalse(config.use_llm)
        self.assertEqual(config.ollama_model, "llama3.1:8b-instruct-q4_K_M")
        self.assertEqual(config.ollama_seed, 42)
        self.assertEqual(config.ollama_temp, 0.0)
        self.assertFalse(config.use_ast_norm)
        self.assertFalse(config.use_morse_decay)
        self.assertTrue(config.use_size_norm)
        self.assertFalse(config.use_bm25_context)
        self.assertEqual(config.alpha_tactic_diversity, 0.25)
        self.assertEqual(config.pseudo_edge_window_sec, 300)
        self.assertEqual(config.top_k_subgraphs, 5)
        self.assertEqual(config.max_events_per_prompt, 25)
        self.assertEqual(
            config.benign_roots,
            (
                "services.exe",
                "svchost.exe",
                "wininit.exe",
                "explorer.exe",
                "lsass.exe",
                "smss.exe",
                "csrss.exe",
            ),
        )

    def test_frozen_schema_columns(self):
        """Verifies the exact 24 columns in strict original order."""
        expected_columns = [
            "record_index",
            "eid",
            "host",
            "timestamp_utc",
            "sysmon_event_id",
            "actor_guid",
            "actor_process",
            "action_type",
            "target_guid",
            "target_entity",
            "command_line",
            "canonical_command_line",
            "logon_guid",
            "user",
            "raw_event_pointer",
            "raw_event_hash",
            "chain_hash",
            "raw_xml",
            "max_sigma_rule_id",
            "max_sigma_title",
            "max_sigma_level",
            "sigma_weight",
            "mitre_tactics",
            "is_malicious_gt",
        ]
        conn = sqlite3.connect(":memory:")
        cur = conn.cursor()
        cur.executescript(SCHEMA_SQL)
        cur.execute("PRAGMA table_info(events)")
        rows = cur.fetchall()
        actual_columns = [r[1] for r in rows]
        conn.close()

        self.assertEqual(len(actual_columns), 24)
        self.assertEqual(actual_columns, expected_columns)

    def test_primary_key_and_eid_contract(self):
        """Verifies primary key and eid format contract."""
        conn = sqlite3.connect(":memory:")
        cur = conn.cursor()
        cur.executescript(SCHEMA_SQL)
        cur.execute("PRAGMA table_info(events)")
        rows = cur.fetchall()
        pk_col = next(r for r in rows if r[5] == 1)
        self.assertEqual(pk_col[1], "record_index")

        # Test insert and eid constraint
        for ev in MOCK_EVENTS:
            self.assertEqual(ev["eid"], f"rec_{ev['record_index']}")
        conn.close()

    def test_mock_generation(self):
        """Tests that mock generator runs and creates valid SQLite and JSONL files."""
        db_path = "data/sqlite_db/mock_trace.db"
        jsonl_path = "data/hayabusa_out/mock_hayabusa.jsonl"
        generate_all()

        self.assertTrue(Path(db_path).exists())
        self.assertTrue(Path(jsonl_path).exists())

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events")
        count = cur.fetchone()[0]
        self.assertEqual(count, len(MOCK_EVENTS))

        # Check raw command line preservation
        cur.execute("SELECT command_line, canonical_command_line FROM events WHERE record_index = 1")
        row = cur.fetchone()
        self.assertEqual(row[0], "powershell.exe -enc SQBFAFgA")
        self.assertIsNone(row[1])

        # Check MITRE tactics JSON serialization
        cur.execute("SELECT mitre_tactics FROM events WHERE record_index = 1")
        tactics_json = cur.fetchone()[0]
        tactics = json.loads(tactics_json)
        self.assertIn("execution", tactics)

        # Check ground truth label isolation
        cur.execute("SELECT is_malicious_gt FROM events WHERE record_index = 1")
        gt = cur.fetchone()[0]
        self.assertEqual(gt, 1)

        conn.close()


if __name__ == "__main__":
    unittest.main()

