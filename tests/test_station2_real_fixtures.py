"""Station 2 tests on small slices of REAL Hayabusa v4.4.0 output (tests/fixtures).

Fixtures are derived from public EVTX-ATTACK-SAMPLES logs (see tests/fixtures/README.md).
"""

import json
import os
import sqlite3
import tempfile
import unittest

from config import PipelineConfig
from event_time import CANONICAL_ORDER_SQL, delta_ms, is_before, parse_ts, within_tolerance
from station1_ingestor import EVENTS_TABLE_SQL
from station2_hayabusa import (
    execute_station2,
    extract_tactics,
    normalize_severity,
    parse_hayabusa_jsonl,
)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
MIMI = "CA_Mimikatz_Memssp_Default_Logs_Sysmon_11"
UACME = "UACME_59_Sysmon"
DE = "DE_sysmon-3-rdp-tun"


def _alerts(name):
    with open(os.path.join(FIX, f"{name}.hayabusa.jsonl"), encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def _build_db(name, tmpdir, mutate=None):
    with open(os.path.join(FIX, f"{name}.events.json"), encoding="utf-8") as f:
        events = json.load(f)
    if mutate:
        events = mutate(events)
    db = os.path.join(tmpdir, f"{name}.db")
    conn = sqlite3.connect(db)
    conn.execute(EVENTS_TABLE_SQL)
    for ev in events:
        cols = list(ev.keys())
        conn.execute(
            f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            [ev[c] for c in cols],
        )
    conn.commit()
    conn.close()
    return db


class TestSeverityAndTacticsOnRealRows(unittest.TestCase):
    def test_real_levels_map_to_weights(self):
        levels = {r["Level"] for n in (MIMI, UACME, DE) for r in _alerts(n)}
        self.assertTrue({"informational", "low", "medium", "high", "critical"} <= levels)
        expected = {"informational": 0.1, "low": 0.3, "medium": 0.6, "high": 0.9, "critical": 1.0}
        for lvl in levels:
            self.assertEqual(normalize_severity(lvl), (lvl, expected[lvl]))

    def test_hayabusa_abbreviations_and_unknown(self):
        self.assertEqual(normalize_severity("info"), ("informational", 0.1))
        self.assertEqual(normalize_severity("med"), ("medium", 0.6))
        self.assertEqual(normalize_severity("crit"), ("critical", 1.0))
        self.assertEqual(normalize_severity("bogus"), ("none", 0.0))
        self.assertEqual(normalize_severity(""), ("none", 0.0))
        self.assertEqual(normalize_severity(None), ("none", 0.0))

    def test_informational_rows_have_no_mitre_keys(self):
        info_rows = [r for r in _alerts(DE) if r["Level"] == "informational"]
        self.assertTrue(info_rows)
        for r in info_rows:
            self.assertNotIn("MitreTactics", r)
            self.assertEqual(extract_tactics(r), [])

    def test_mitre_tags_are_not_tactics(self):
        crit = [r for r in _alerts(MIMI) if r["Level"] == "critical"][0]
        self.assertEqual(crit["MitreTags"], ["T1558"])
        self.assertEqual(extract_tactics(crit), ["credaccess"])
        self.assertEqual(extract_tactics({"MitreTags": ["T1036"]}), [])
        self.assertEqual(extract_tactics({"MitreTactics": None}), [])


class TestAggregationOnRealRows(unittest.TestCase):
    def test_mimikatz_critical_wins_over_informational(self):
        aggs, total, malformed, field = parse_hayabusa_jsonl(os.path.join(FIX, f"{MIMI}.hayabusa.jsonl"))
        self.assertEqual((total, malformed, field), (2, 0, "RecordID"))
        a = aggs[385052]
        self.assertEqual(a.max_level, "critical")
        self.assertEqual(a.max_weight, 1.0)
        self.assertEqual(a.max_title, "HackTool - Mimikatz Kirbi File Creation")
        self.assertEqual(a.tactics, ["credaccess"])
        self.assertEqual(a.channel, "microsoft-windows-sysmon/operational")
        self.assertEqual(a.computer, "msedgewin10")

    def test_de_multi_rule_event_merges_tactics(self):
        aggs, _, _, _ = parse_hayabusa_jsonl(os.path.join(FIX, f"{DE}.hayabusa.jsonl"))
        a = aggs[1940899]  # plink: informational + high + 2x medium
        self.assertEqual(a.max_level, "high")
        self.assertEqual(a.max_title, "Suspicious Plink Port Forwarding")
        self.assertEqual(a.tactics, ["c2", "exfil", "latmov"])
        self.assertEqual(aggs[1940909].max_level, "informational")
        self.assertEqual(aggs[1940909].tactics, [])

    def test_uacme_low_with_stealth(self):
        aggs, _, _, _ = parse_hayabusa_jsonl(os.path.join(FIX, f"{UACME}.hayabusa.jsonl"))
        a = aggs[2164892]
        self.assertEqual((a.max_level, a.max_weight), ("low", 0.3))
        self.assertEqual(a.tactics, ["stealth"])


class TestCompositeJoinOnRealRows(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_primary_join_de(self):
        db = _build_db(DE, self.tmp.name)
        res = execute_station2(db, os.path.join(FIX, f"{DE}.hayabusa.jsonl"), PipelineConfig())
        self.assertEqual(res["primary_matched_records"], 9)
        self.assertEqual(res["fallback_matched_records"], 0)
        self.assertEqual(res["join_hit_rate"], 1.0)
        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT max_sigma_level, sigma_weight, mitre_tactics FROM events WHERE record_index=1940899"
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "high")
        self.assertEqual(row[1], 0.9)
        self.assertEqual(json.loads(row[2]), ["c2", "exfil", "latmov"])

    def test_same_recordid_different_channel_is_not_joined(self):
        def to_security(evs):
            for e in evs:
                e["raw_xml"] = e["raw_xml"].replace(
                    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>", "<Channel>Security</Channel>"
                )
            return evs

        db = _build_db(MIMI, self.tmp.name, mutate=to_security)
        with self.assertLogs("station2_hayabusa", level="WARNING") as cm:
            res = execute_station2(db, os.path.join(FIX, f"{MIMI}.hayabusa.jsonl"), PipelineConfig())
        self.assertEqual(res["matched_sigma_records"], 0)
        self.assertTrue(any("mismatch" in m for m in cm.output))

    def test_same_recordid_different_computer_is_not_joined(self):
        def other_host(evs):
            for e in evs:
                e["host"] = "OTHER-HOST"
            return evs

        db = _build_db(MIMI, self.tmp.name, mutate=other_host)
        with self.assertLogs("station2_hayabusa", level="WARNING"):
            res = execute_station2(db, os.path.join(FIX, f"{MIMI}.hayabusa.jsonl"), PipelineConfig())
        self.assertEqual(res["matched_sigma_records"], 0)

    def test_missing_channel_falls_back_with_warning(self):
        def no_channel(evs):
            for e in evs:
                e["raw_xml"] = e["raw_xml"].replace(
                    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>", ""
                )
            return evs

        db = _build_db(MIMI, self.tmp.name, mutate=no_channel)
        with self.assertLogs("station2_hayabusa", level="WARNING") as cm:
            res = execute_station2(db, os.path.join(FIX, f"{MIMI}.hayabusa.jsonl"), PipelineConfig())
        self.assertEqual(res["fallback_matched_records"], 1)
        self.assertTrue(any("Falling back" in m for m in cm.output))


class TestCanonicalTime(unittest.TestCase):
    def test_db_time_equals_hayabusa_timestamp(self):
        with open(os.path.join(FIX, f"{MIMI}.events.json"), encoding="utf-8") as f:
            ev = json.load(f)[0]
        hb = _alerts(MIMI)[0]
        self.assertEqual(delta_ms(ev["timestamp_utc"], hb["Timestamp"]), 0.0)

    def test_sysmon_utctime_skew_within_tolerance(self):
        hb = _alerts(MIMI)[0]
        d = delta_ms(hb["Timestamp"], hb["Details"]["UtcTime"] + "Z")
        self.assertAlmostEqual(d, 41.0, places=3)
        tol = PipelineConfig().temporal_tolerance_ms
        self.assertTrue(within_tolerance(hb["Timestamp"], hb["Details"]["UtcTime"] + "Z", tol))
        self.assertFalse(is_before(hb["Details"]["UtcTime"] + "Z", hb["Timestamp"], tol))

    def test_canonical_order_is_time_then_recordid(self):
        db_dir = tempfile.TemporaryDirectory()
        try:
            db = _build_db(DE, db_dir.name)
            conn = sqlite3.connect(db)
            rows = conn.execute(f"SELECT timestamp_utc, record_index FROM events {CANONICAL_ORDER_SQL}").fetchall()
            conn.close()
            keys = [(parse_ts(t), r) for t, r in rows]
            self.assertEqual(keys, sorted(keys))
        finally:
            db_dir.cleanup()

    def test_unparseable_never_equal(self):
        self.assertFalse(within_tolerance(None, "2020-01-01T00:00:00.000Z", 10_000))
        self.assertFalse(within_tolerance("garbage", "garbage", 10_000))


if __name__ == "__main__":
    unittest.main()
