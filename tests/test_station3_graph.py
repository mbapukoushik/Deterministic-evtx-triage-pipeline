"""Station 3 logic tests (graph rules + scoring). No evaluation numbers are asserted here."""

import json
import math
import os
import sqlite3
import tempfile
import unittest
from dataclasses import replace

import networkx as nx

from config import PipelineConfig
from station1_ingestor import EVENTS_TABLE_SQL
from station2_hayabusa import execute_station2
from station3_graph_scorer import (
    EDGE_FILE,
    EDGE_LINEAGE,
    EDGE_REG,
    build_graph,
    load_events,
    rank_subgraphs,
)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

G_SVC = "{AAAAAAAA-0000-0000-0000-000000000001}"
G_A = "{AAAAAAAA-0000-0000-0000-00000000000A}"
G_B = "{AAAAAAAA-0000-0000-0000-00000000000B}"
G_C = "{AAAAAAAA-0000-0000-0000-00000000000C}"
G_D = "{AAAAAAAA-0000-0000-0000-00000000000D}"
LOGON = "{AAAAAAAA-0000-0000-0000-0000000003E7}"


def ev(rid, ts, action, actor_guid, actor_proc, target_guid=None, target=None, cmd=None,
       weight=0.0, level="none", tactics=None, logon=LOGON):
    return {
        "record_index": rid, "eid": f"rec_{rid}", "host": "LAB", "timestamp_utc": ts,
        "sysmon_event_id": 1, "actor_guid": actor_guid, "actor_process": actor_proc,
        "action_type": action, "target_guid": target_guid, "target_entity": target,
        "command_line": cmd, "logon_guid": logon, "user": "LAB\\u",
        "sigma_weight": weight, "max_sigma_level": level,
        "mitre_tactics": json.dumps(tactics) if tactics else None,
    }


def make_db(tmpdir, events, name="t.db"):
    path = os.path.join(tmpdir, name)
    conn = sqlite3.connect(path)
    conn.execute(EVENTS_TABLE_SQL)
    for e in events:
        cols = list(e.keys())
        conn.execute(f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                     [e[c] for c in cols])
    conn.commit()
    conn.close()
    return path


SVC = r"C:\Windows\System32\svchost.exe"
CMD = r"C:\Windows\System32\cmd.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
DROP = r"C:\Users\Public\updater.exe"


class Station3Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = PipelineConfig()

    def tearDown(self):
        self.tmp.cleanup()

    def graph(self, events, cfg=None):
        db = make_db(self.tmp.name, events)
        return build_graph(load_events(db), cfg or self.cfg), db


class TestLineage(Station3Base):
    def test_parent_child_lineage(self):
        g, _ = self.graph([
            ev(1, "2026-01-01T00:00:00.000Z", "PROCESS_CREATE", G_A, CMD, G_B, PS),
            ev(2, "2026-01-01T00:00:01.000Z", "NETWORK_CONNECT", G_B, PS, None, "10.0.0.5"),
        ])
        self.assertTrue(g.has_edge(1, 2))
        self.assertIn(EDGE_LINEAGE, g.edges[1, 2]["types"])

    def test_benign_root_does_not_merge_unrelated_children(self):
        g, _ = self.graph([
            ev(1, "2026-01-01T00:00:00.000Z", "PROCESS_CREATE", G_SVC, SVC, G_A, CMD),
            ev(2, "2026-01-01T00:00:01.000Z", "PROCESS_CREATE", G_SVC, SVC, G_B, PS),
            ev(3, "2026-01-01T00:00:02.000Z", "NETWORK_CONNECT", G_A, CMD, None, "10.0.0.1"),
            ev(4, "2026-01-01T00:00:03.000Z", "NETWORK_CONNECT", G_B, PS, None, "10.0.0.2"),
        ])
        self.assertFalse(g.has_edge(1, 2))  # svchost same-actor chain cut
        comps = [sorted(c) for c in nx.weakly_connected_components(g)]
        self.assertIn([1, 3], comps)
        self.assertIn([2, 4], comps)

    def test_shared_logon_guid_never_correlates(self):
        g, _ = self.graph([
            ev(1, "2026-01-01T00:00:00.000Z", "NETWORK_CONNECT", G_A, CMD, None, "1.1.1.1"),
            ev(2, "2026-01-01T00:00:01.000Z", "NETWORK_CONNECT", G_C, PS, None, "2.2.2.2"),
        ])
        self.assertEqual(g.number_of_edges(), 0)

    def test_graph_is_dag_and_time_forward(self):
        g, db = self.graph([
            ev(2, "2026-01-01T00:00:05.000Z", "NETWORK_CONNECT", G_B, PS, None, "1.1.1.1"),
            ev(1, "2026-01-01T00:00:00.000Z", "PROCESS_CREATE", G_A, CMD, G_B, PS),
            ev(3, "2026-01-01T00:00:05.000Z", "DNS_QUERY", G_B, PS, None, "x.test"),
        ])
        self.assertTrue(nx.is_directed_acyclic_graph(g))
        order = {e["record_index"]: e["_order"] for e in load_events(db)}
        for u, v in g.edges():
            self.assertLess(order[u], order[v])
        # equal timestamps are ordered by record_index
        self.assertLess(order[2], order[3])


class TestPseudoEdges(Station3Base):
    def _file_events(self, delta_sec):
        return [
            ev(1, "2026-01-01T00:00:00.000Z", "FILE_CREATE", G_A, CMD, None, DROP),
            ev(2, f"2026-01-01T00:{delta_sec // 60:02d}:{delta_sec % 60:02d}.000Z",
               "PROCESS_CREATE", G_C, PS, G_D, DROP.upper()),
        ]

    def test_file_bridge_inside_window(self):
        g, _ = self.graph(self._file_events(300))
        self.assertIn(EDGE_FILE, g.edges[1, 2]["types"])

    def test_file_bridge_outside_window(self):
        g, _ = self.graph(self._file_events(301))
        self.assertFalse(g.has_edge(1, 2))

    def test_file_bridge_window_is_configurable(self):
        g, _ = self.graph(self._file_events(301), replace(self.cfg, pseudo_edge_window_sec=900))
        self.assertTrue(g.has_edge(1, 2))

    def test_registry_bridge(self):
        g, _ = self.graph([
            ev(1, "2026-01-01T00:00:00.000Z", "REGISTRY_EVENT", G_A, PS, None,
               r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater", cmd=DROP),
            ev(2, "2026-01-01T00:01:00.000Z", "PROCESS_CREATE", G_C, r"C:\Windows\System32\userinit.exe",
               G_D, DROP, cmd=f'"{DROP}" /silent'),
        ])
        self.assertIn(EDGE_REG, g.edges[1, 2]["types"])

    def test_registry_bridge_needs_executable_path(self):
        g, _ = self.graph([
            ev(1, "2026-01-01T00:00:00.000Z", "REGISTRY_EVENT", G_A, PS, None, r"HKCU\x", cmd="DWORD (0x00000001)"),
            ev(2, "2026-01-01T00:00:10.000Z", "PROCESS_CREATE", G_C, CMD, G_D, DROP),
        ])
        self.assertFalse(g.has_edge(1, 2))


class TestScoring(Station3Base):
    def _two_chains(self):
        return [
            ev(1, "2026-01-01T00:00:00.000Z", "PROCESS_CREATE", G_A, CMD, G_B, PS, weight=0.9, tactics=["execution"]),
            ev(2, "2026-01-01T00:00:01.000Z", "PROCESS_ACCESS", G_B, PS, None, "lsass.exe", weight=1.0, tactics=["credaccess"]),
            ev(3, "2026-01-01T00:00:02.000Z", "NETWORK_CONNECT", G_C, CMD, None, "1.1.1.1", weight=0.1),
        ]

    def test_formula_size_norm(self):
        db = make_db(self.tmp.name, self._two_chains())
        doc = rank_subgraphs(db, self.cfg)
        top = doc["subgraphs"][0]
        self.assertEqual(top["all_eids"], ["rec_1", "rec_2"])
        expected = (1 + 0.25 * 2) * 1.0 * math.log1p(1.9)
        self.assertAlmostEqual(top["score"], round(expected, 6), places=6)

    def test_formula_unnormalized_ablation(self):
        db = make_db(self.tmp.name, self._two_chains())
        doc = rank_subgraphs(db, replace(self.cfg, use_size_norm=False))
        self.assertAlmostEqual(doc["subgraphs"][0]["score"], round((1 + 0.5) * 1.0 * 1.9, 6), places=6)

    def test_morse_decay_attenuates_below_benign_root(self):
        events = [
            ev(1, "2026-01-01T00:00:00.000Z", "PROCESS_CREATE", G_SVC, SVC, G_A, CMD, weight=0.3),
            ev(2, "2026-01-01T00:00:01.000Z", "PROCESS_CREATE", G_A, CMD, G_B, PS, weight=0.9),
        ]
        db = make_db(self.tmp.name, events)
        base = rank_subgraphs(db, self.cfg)["subgraphs"][0]["score"]
        decayed = rank_subgraphs(db, replace(self.cfg, use_morse_decay=True))["subgraphs"][0]["score"]
        self.assertLess(decayed, base)

    def test_prompt_cap_keeps_highest_weight_and_is_chronological(self):
        events = [ev(1, "2026-01-01T00:00:00.000Z", "PROCESS_CREATE", G_A, CMD, G_B, PS, weight=0.1)]
        for i in range(2, 40):
            w = 1.0 if i == 39 else 0.1
            events.append(ev(i, f"2026-01-01T00:00:{i:02d}.000Z", "DNS_QUERY", G_B, PS, None, f"h{i}.test", weight=w))
        db = make_db(self.tmp.name, events)
        sg = rank_subgraphs(db, self.cfg)["subgraphs"][0]
        self.assertEqual(sg["n_events"], 39)
        self.assertEqual(len(sg["events"]), 25)
        self.assertTrue(sg["truncated"])
        self.assertIn("rec_39", sg["prompt_eids"])
        ts = [e["timestamp_utc"] for e in sg["events"]]
        self.assertEqual(ts, sorted(ts))

    def test_ranking_is_deterministic(self):
        db = make_db(self.tmp.name, self._two_chains())
        a = rank_subgraphs(db, self.cfg)
        b = rank_subgraphs(db, self.cfg)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_ground_truth_column_not_exposed(self):
        db = make_db(self.tmp.name, self._two_chains())
        doc = rank_subgraphs(db, self.cfg)
        for sg in doc["subgraphs"]:
            for e in sg["events"]:
                self.assertNotIn("is_malicious_gt", e)


class TestRealFixtureLogic(unittest.TestCase):
    """Logic check on the real DE_sysmon-3-rdp-tun slice: plink lineage must connect."""

    def test_plink_process_and_its_connection_are_linked(self):
        with open(os.path.join(FIX, "DE_sysmon-3-rdp-tun.events.json"), encoding="utf-8") as f:
            events = json.load(f)
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp, events)
            execute_station2(db, os.path.join(FIX, "DE_sysmon-3-rdp-tun.hayabusa.jsonl"), PipelineConfig())
            g = build_graph(load_events(db), PipelineConfig())
            self.assertTrue(g.has_edge(1940899, 1940901))
            self.assertTrue(g.has_edge(1940901, 1940919))
            doc = rank_subgraphs(db, PipelineConfig())
            self.assertEqual(doc["subgraphs"][0]["all_eids"][0], "rec_1940899")


if __name__ == "__main__":
    unittest.main()
