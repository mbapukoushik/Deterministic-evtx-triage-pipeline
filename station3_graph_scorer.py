"""Station 3: Event-centric provenance graph reconstruction & subgraph priority scoring.

TEAM T12 - DFIR Pipeline. See README_SPEC.md §Station 3 for the frozen rules.

Graph G = (V, E): one node per events row (record_index). Edges always point from an
earlier to a later event in canonical order (timestamp_utc, record_index), so G is a DAG.

Edge types (the ONLY correlation channels permitted):
  PROCESS_LINEAGE  ParentProcessGuid -> ProcessGuid identity:
                   (a) PROCESS_CREATE e_a with target_guid P  ->  every later e_b with actor_guid P
                   (b) consecutive events of the same actor_guid P (chronological chain)
                   Skipped when the shared process image basename is in cfg.benign_roots.
  FILE_BRIDGE      FILE_CREATE e_a -> PROCESS_CREATE e_b, same path (case-insensitive),
                   0 <= t_b - t_a <= cfg.pseudo_edge_window_sec.
  REGISTRY_BRIDGE  REGISTRY_EVENT e_a -> PROCESS_CREATE e_b, executable path written in e_a
                   appears in e_b.target_entity or e_b.command_line, same window.

Never used for correlation: logon_guid, LogonId, ProcessId, user, host.

Scoring per weakly connected component G_k:
  S_norm = (1 + alpha*|T(G_k)|) * max w(e) * ln(1 + sum w(e))      (use_size_norm=True)
  S_raw  = (1 + alpha*|T(G_k)|) * max w(e) * sum w(e)              (use_size_norm=False)
  use_morse_decay=True: w(e) *= 0.5**d(e), d = PROCESS_LINEAGE hop distance from the nearest
  event whose actor is a benign root (events with no benign-root ancestor: d = 0).
"""

import argparse
import json
import math
import os
import re
import sqlite3
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from config import PipelineConfig, config
from event_time import CANONICAL_ORDER_SQL, delta_ms

EDGE_LINEAGE = "PROCESS_LINEAGE"
EDGE_FILE = "FILE_BRIDGE"
EDGE_REG = "REGISTRY_BRIDGE"

_EXE_PATH_RE = re.compile(
    r"([a-zA-Z]:\\[^\"'<>|\r\n]*?\.(?:exe|dll|bat|cmd|ps1|vbs|js|hta|scr|com))",
    re.IGNORECASE,
)

EVENT_COLUMNS = [
    "record_index", "eid", "host", "timestamp_utc", "sysmon_event_id", "actor_guid",
    "actor_process", "action_type", "target_guid", "target_entity", "command_line",
    "canonical_command_line", "user", "raw_event_pointer", "max_sigma_rule_id",
    "max_sigma_title", "max_sigma_level", "sigma_weight", "mitre_tactics",
]


def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


def _norm_guid(g: Optional[str]) -> Optional[str]:
    if not g or not isinstance(g, str):
        return None
    s = g.strip().strip("{}").upper()
    return s or None


def _tactics(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        val = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [str(t) for t in val] if isinstance(val, list) else []


def load_events(db_path: str) -> List[Dict[str, Any]]:
    """Loads events in canonical order (timestamp_utc, record_index). Excludes is_malicious_gt."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            f"SELECT {','.join(EVENT_COLUMNS)} FROM events {CANONICAL_ORDER_SQL}"
        ).fetchall()
    finally:
        conn.close()
    events = []
    for order, row in enumerate(rows):
        ev = dict(zip(EVENT_COLUMNS, row))
        ev["_order"] = order
        ev["_actor_guid"] = _norm_guid(ev["actor_guid"])
        ev["_target_guid"] = _norm_guid(ev["target_guid"])
        ev["_tactics"] = _tactics(ev["mitre_tactics"])
        ev["sigma_weight"] = float(ev["sigma_weight"] or 0.0)
        events.append(ev)
    return events


def _process_images(events: List[Dict[str, Any]]) -> Dict[str, str]:
    """Best-known image basename per ProcessGuid (from actor or PROCESS_CREATE target)."""
    images: Dict[str, str] = {}
    for ev in events:
        if ev["_actor_guid"] and ev["actor_process"]:
            images.setdefault(ev["_actor_guid"], _basename(ev["actor_process"]))
        if ev["action_type"] == "PROCESS_CREATE" and ev["_target_guid"] and ev["target_entity"]:
            images[ev["_target_guid"]] = _basename(ev["target_entity"])
    return images


def build_graph(events: List[Dict[str, Any]], cfg: PipelineConfig = config) -> nx.DiGraph:
    """Builds the event-centric provenance DAG."""
    g = nx.DiGraph()
    for ev in events:
        g.add_node(ev["record_index"], order=ev["_order"])

    benign = {b.lower() for b in cfg.benign_roots}
    images = _process_images(events)
    window_ms = cfg.pseudo_edge_window_sec * 1000.0

    def add_edge(a: Dict[str, Any], b: Dict[str, Any], etype: str) -> None:
        if a["_order"] >= b["_order"]:
            return
        u, v = a["record_index"], b["record_index"]
        if g.has_edge(u, v):
            types = g.edges[u, v]["types"]
            if etype not in types:
                types.append(etype)
        else:
            g.add_edge(u, v, types=[etype])

    # --- PROCESS_LINEAGE -------------------------------------------------------------
    by_actor: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["_actor_guid"]:
            by_actor[ev["_actor_guid"]].append(ev)

    # (a) creation event of P -> events performed by P
    for ev in events:
        p = ev["_target_guid"]
        if ev["action_type"] != "PROCESS_CREATE" or not p:
            continue
        if images.get(p, "") in benign:
            continue
        for child in by_actor.get(p, []):
            add_edge(ev, child, EDGE_LINEAGE)

    # (b) chronological chain of events performed by the same P
    for p, evs in by_actor.items():
        if images.get(p, "") in benign:
            continue
        for a, b in zip(evs, evs[1:]):
            add_edge(a, b, EDGE_LINEAGE)

    # --- FILE_BRIDGE / REGISTRY_BRIDGE -----------------------------------------------
    proc_creates = [ev for ev in events if ev["action_type"] == "PROCESS_CREATE"]

    def in_window(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        if a["_order"] >= b["_order"]:
            return False
        d = delta_ms(b["timestamp_utc"], a["timestamp_utc"])
        return d is not None and d <= window_ms

    for a in events:
        if a["action_type"] == "FILE_CREATE" and a["target_entity"]:
            path = a["target_entity"].strip().lower()
            for b in proc_creates:
                if b["target_entity"] and b["target_entity"].strip().lower() == path and in_window(a, b):
                    add_edge(a, b, EDGE_FILE)
        elif a["action_type"] == "REGISTRY_EVENT" and a["command_line"]:
            written = [m.lower() for m in _EXE_PATH_RE.findall(a["command_line"])]
            if not written:
                continue
            for b in proc_creates:
                hay = " ".join(x for x in (b["target_entity"], b["command_line"]) if x).lower()
                if any(w in hay for w in written) and in_window(a, b):
                    add_edge(a, b, EDGE_REG)

    return g


def _morse_distances(
    g: nx.DiGraph, events_by_id: Dict[int, Dict[str, Any]], cfg: PipelineConfig
) -> Dict[int, int]:
    """Hop distance along PROCESS_LINEAGE edges from the nearest benign-root-actor event."""
    benign = {b.lower() for b in cfg.benign_roots}
    dist: Dict[int, int] = {}
    q: deque = deque()
    for rid, ev in events_by_id.items():
        if _basename(ev["actor_process"]) in benign:
            dist[rid] = 0
            q.append(rid)
    while q:
        u = q.popleft()
        for v in g.successors(u):
            if EDGE_LINEAGE in g.edges[u, v]["types"] and v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return {rid: dist.get(rid, 0) for rid in events_by_id}


def score_component(
    nodes: List[int],
    events_by_id: Dict[int, Dict[str, Any]],
    cfg: PipelineConfig,
    decay: Optional[Dict[int, int]] = None,
) -> Dict[str, Any]:
    weights = []
    tactics = set()
    for rid in nodes:
        w = events_by_id[rid]["sigma_weight"]
        if decay is not None:
            w *= 0.5 ** decay.get(rid, 0)
        weights.append(w)
        tactics.update(events_by_id[rid]["_tactics"])
    w_max = max(weights) if weights else 0.0
    w_sum = sum(weights)
    mass = math.log1p(w_sum) if cfg.use_size_norm else w_sum
    score = (1.0 + cfg.alpha_tactic_diversity * len(tactics)) * w_max * mass
    return {
        "score": score,
        "max_weight": w_max,
        "sum_weight": w_sum,
        "tactics": sorted(tactics),
    }


def _select_prompt_events(
    nodes: List[int], events_by_id: Dict[int, Dict[str, Any]], cap: int
) -> List[int]:
    """Top-`cap` events by sigma_weight (deterministic tie-break by order, then RecordID), returned chronologically."""
    ranked = sorted(
        nodes,
        key=lambda r: (-events_by_id[r]["sigma_weight"], events_by_id[r]["_order"], r),
    )
    keep = ranked[:cap]
    return sorted(keep, key=lambda r: (events_by_id[r]["_order"], r))


def _public_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    return {k: ev[k] for k in EVENT_COLUMNS if k != "mitre_tactics"} | {"mitre_tactics": ev["_tactics"]}


def rank_subgraphs(db_path: str, cfg: PipelineConfig = config) -> Dict[str, Any]:
    """Runs Station 3 end-to-end on one trace DB and returns the ranked-subgraphs document."""
    events = load_events(db_path)
    events_by_id = {ev["record_index"]: ev for ev in events}
    g = build_graph(events, cfg)
    decay = _morse_distances(g, events_by_id, cfg) if cfg.use_morse_decay else None

    comps = []
    for comp in nx.weakly_connected_components(g):
        nodes = sorted(comp, key=lambda r: events_by_id[r]["_order"])
        s = score_component(nodes, events_by_id, cfg, decay)
        comps.append((nodes, s))

    # Deterministic ranking: score desc, then earliest event first, then smallest record_index.
    comps.sort(key=lambda c: (-c[1]["score"], events_by_id[c[0][0]]["_order"], c[0][0]))

    edge_counts: Dict[str, int] = defaultdict(int)
    for _, _, d in g.edges(data=True):
        for t in d["types"]:
            edge_counts[t] += 1

    out_subgraphs = []
    for rank, (nodes, s) in enumerate(comps[: cfg.top_k_subgraphs], start=1):
        node_set = set(nodes)
        prompt_ids = _select_prompt_events(nodes, events_by_id, cfg.max_events_per_prompt)
        edges = [
            {"src": f"rec_{u}", "dst": f"rec_{v}", "types": d["types"]}
            for u, v, d in g.edges(data=True)
            if u in node_set and v in node_set
        ]
        edges.sort(key=lambda e: (events_by_id[int(e["src"][4:])]["_order"], events_by_id[int(e["dst"][4:])]["_order"]))
        out_subgraphs.append(
            {
                "subgraph_id": f"sg_{rank}",
                "rank": rank,
                "score": round(s["score"], 6),
                "n_events": len(nodes),
                "max_weight": s["max_weight"],
                "sum_weight": round(s["sum_weight"], 6),
                "tactics": s["tactics"],
                "all_eids": [f"rec_{r}" for r in nodes],
                "prompt_eids": [f"rec_{r}" for r in prompt_ids],
                "truncated": len(nodes) > len(prompt_ids),
                "edges": edges,
                "events": [_public_event(events_by_id[r]) for r in prompt_ids],
            }
        )

    return {
        "db": os.path.basename(db_path),
        "config": {
            "alpha_tactic_diversity": cfg.alpha_tactic_diversity,
            "pseudo_edge_window_sec": cfg.pseudo_edge_window_sec,
            "top_k_subgraphs": cfg.top_k_subgraphs,
            "max_events_per_prompt": cfg.max_events_per_prompt,
            "use_size_norm": cfg.use_size_norm,
            "use_morse_decay": cfg.use_morse_decay,
            "benign_roots": list(cfg.benign_roots),
        },
        "graph_stats": {
            "n_events": g.number_of_nodes(),
            "n_edges": g.number_of_edges(),
            "edges_by_type": dict(sorted(edge_counts.items())),
            "n_components": len(comps),
        },
        "subgraphs": out_subgraphs,
    }


def execute_station3(db_path: str, out_json: str, cfg: PipelineConfig = config) -> Dict[str, Any]:
    doc = rank_subgraphs(db_path, cfg)
    os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Station 3: provenance graph + subgraph ranking")
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    doc = execute_station3(args.db, args.out)
    print(json.dumps(doc["graph_stats"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
