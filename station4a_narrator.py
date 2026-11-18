"""Station 4A: Deterministic M2 Incident Narration Engine.

TEAM T12 - DFIR Pipeline.
Implements the deterministic M2 extractive template baseline (no LLM yet).
- States "{shown} of {total} events shown" for every subgraph.
- Treats events closer than cfg.temporal_tolerance_ms as "unordered" in the narrative note.
- Emits structured claim tuples for deterministic verification in Station 4B.
"""

import argparse
import json
import os
from typing import Any, Dict, List, Optional

from config import PipelineConfig, config
from event_time import temporal_relation


def format_m2_sentence(ev: Dict[str, Any], unordered_with_prev: bool = False) -> str:
    """Formats a single event row into the deterministic M2 extractive template."""
    ts = ev.get("timestamp_utc") or "UNKNOWN_TIME"
    host = ev.get("host") or "UNKNOWN_HOST"
    actor = ev.get("actor_process") or "UNKNOWN_ACTOR"
    actor_guid = ev.get("actor_guid")
    action = ev.get("action_type") or "UNKNOWN_ACTION"
    target = ev.get("target_entity") or "UNKNOWN_TARGET"
    cmd = ev.get("canonical_command_line") or ev.get("command_line")
    sigma_id = ev.get("max_sigma_rule_id")
    sigma_lvl = ev.get("max_sigma_level")
    eid = ev.get("eid") or f"rec_{ev.get('record_index')}"
    ptr = ev.get("raw_event_pointer")

    actor_part = f"{actor} ({actor_guid})" if actor_guid else actor
    cmd_part = f" [Cmd: {cmd}]" if cmd else ""

    sigma_bits = []
    if sigma_id:
        sigma_bits.append(f"Sigma: {sigma_id}")
    if sigma_lvl and str(sigma_lvl).lower() != "none":
        sigma_bits.append(f"Level: {sigma_lvl}")
    if ptr:
        sigma_bits.append(f"eid={eid}, ptr={ptr}")
    else:
        sigma_bits.append(f"eid={eid}")

    order_note = " [unordered within temporal tolerance]" if unordered_with_prev else ""
    return (
        f"[{ts}]{order_note} Host {host}: {actor_part} performed {action} on {target}"
        f"{cmd_part} ({', '.join(sigma_bits)})."
    )


def build_m2_claim(ev: Dict[str, Any], unordered_with_prev: bool = False) -> Dict[str, Any]:
    """Builds a structured claim tuple + deterministic M2 sentence for Station 4B."""
    eid = ev.get("eid") or f"rec_{ev.get('record_index')}"
    return {
        "eid": eid,
        "record_index": ev.get("record_index"),
        "timestamp_utc": ev.get("timestamp_utc"),
        "actor_process": ev.get("actor_process"),
        "action_type": ev.get("action_type"),
        "target_entity": ev.get("target_entity"),
        "unordered_with_prev": unordered_with_prev,
        "narrative_sentence": format_m2_sentence(ev, unordered_with_prev=unordered_with_prev),
    }


def narrate_subgraph_m2(sg: Dict[str, Any], cfg: PipelineConfig = config) -> Dict[str, Any]:
    """Generates the deterministic M2 narrative and claim tuples for one ranked subgraph."""
    events = sg.get("events", [])
    total_events = int(sg.get("n_events", len(events)))
    shown = len(events)
    summary_header = f"{shown} of {total_events} events shown"

    claims: List[Dict[str, Any]] = []
    prev_ts: Optional[str] = None
    for ev in events:
        cur_ts = ev.get("timestamp_utc")
        unordered = False
        if prev_ts is not None and cur_ts is not None:
            rel = temporal_relation(prev_ts, cur_ts, cfg.temporal_tolerance_ms)
            unordered = rel == "unordered"
        claims.append(build_m2_claim(ev, unordered_with_prev=unordered))
        prev_ts = cur_ts

    return {
        "subgraph_id": sg.get("subgraph_id"),
        "rank": sg.get("rank"),
        "score": sg.get("score"),
        "events_shown": shown,
        "total_events": total_events,
        "summary_header": summary_header,
        "mode": "M2_DETERMINISTIC",
        "claims": claims,
    }


def narrate_ranked_subgraphs(
    ranked_doc: Dict[str, Any],
    cfg: PipelineConfig = config,
) -> Dict[str, Any]:
    """Generates deterministic M2 narration for all ranked subgraphs."""
    if cfg.use_llm:
        raise NotImplementedError("LLM narration mode is deferred; use deterministic M2 (use_llm=False).")

    subgraphs_out = [
        narrate_subgraph_m2(sg, cfg=cfg) for sg in ranked_doc.get("subgraphs", [])
    ]
    return {
        "db": ranked_doc.get("db"),
        "mode": "M2_DETERMINISTIC",
        "temporal_tolerance_ms": cfg.temporal_tolerance_ms,
        "subgraphs": subgraphs_out,
    }


def execute_station4a(
    ranked_json_path: str,
    out_json_path: str,
    cfg: PipelineConfig = config,
) -> Dict[str, Any]:
    with open(ranked_json_path, "r", encoding="utf-8") as f:
        ranked_doc = json.load(f)
    doc = narrate_ranked_subgraphs(ranked_doc, cfg=cfg)
    os.makedirs(os.path.dirname(os.path.abspath(out_json_path)), exist_ok=True)
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Station 4A: Deterministic M2 Narrator")
    ap.add_argument("--ranked", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    doc = execute_station4a(args.ranked, args.out)
    print(json.dumps({"subgraphs": len(doc["subgraphs"]), "mode": doc["mode"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
