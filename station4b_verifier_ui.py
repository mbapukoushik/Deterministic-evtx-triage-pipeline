"""Station 4B: Deterministic SQLite Tuple & Temporal Verifier with M2 Fallback.

TEAM T12 - DFIR Pipeline.
Verifies every claim against the full SQLite `events` table:
1. Relational Tuple Check: exact match on (timestamp_utc, actor_process, action_type, target_entity).
2. Temporal Contradiction Check (RCA_temporal): checks chronological order across consecutive
   claims; events closer than cfg.temporal_tolerance_ms are treated as 'unordered' (never
   flagged as a contradiction).
3. Closed-Vocabulary / Injection Residual Check: rejects claims containing unexpected
   instruction/speculative tokens outside the allowed M2 template & raw DB fields.
4. Deterministic Fallback: any failing claim is replaced with the M2 template sentence built
   directly from the full SQLite DB row, and pre/post-fallback metrics are recorded.
"""

import argparse
import json
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from config import PipelineConfig, config
from event_time import is_before
from station4a_narrator import format_m2_sentence

DB_VERIFY_COLUMNS = [
    "record_index", "eid", "host", "timestamp_utc", "sysmon_event_id",
    "actor_guid", "actor_process", "action_type", "target_guid", "target_entity",
    "command_line", "canonical_command_line", "raw_event_pointer",
    "max_sigma_rule_id", "max_sigma_level",
]

# Speculative / prompt-injection residual tokens that must not appear in verified narrative
# unless they already exist verbatim in the raw DB fields for that event.
FORBIDDEN_RESIDUAL_PATTERNS = (
    re.compile(r"(?i)\bignore\s+previous\s+instructions\b"),
    re.compile(r"(?i)\bsystem\s+prompt\b"),
    re.compile(r"(?i)\bprobably\b|\blikely\b|\bmight\s+have\b|\bpossibly\b|\bassumed\b"),
)


def _fetch_db_event(conn: sqlite3.Connection, eid: str) -> Optional[Dict[str, Any]]:
    row = conn.execute(
        f"SELECT {','.join(DB_VERIFY_COLUMNS)} FROM events WHERE eid = ?",
        (eid,),
    ).fetchone()
    if row is None:
        return None
    return dict(zip(DB_VERIFY_COLUMNS, row))


def _norm_field(val: Optional[str]) -> str:
    return "" if val is None else str(val).strip()


def _check_closed_vocabulary(sentence: str, db_ev: Dict[str, Any]) -> Optional[str]:
    """Rejects speculative/injection text not present verbatim in the raw DB event."""
    raw_blob = " ".join(
        str(db_ev.get(k) or "")
        for k in ("actor_process", "target_entity", "command_line", "canonical_command_line", "host")
    )
    # Strip raw command_line / target_entity substrings so legitimate raw log content isn't penalized
    # unless the narrator echoed an injection outside the [Cmd: ...] bracket.
    scrubbed = sentence
    for pat in FORBIDDEN_RESIDUAL_PATTERNS:
        m = pat.search(scrubbed)
        if m and m.group(0).lower() not in raw_blob.lower():
            return f"forbidden_vocabulary:{m.group(0)}"
    return None


def verify_claim_tuple(claim: Dict[str, Any], db_ev: Optional[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Checks claim tuple against the full SQLite DB row."""
    if db_ev is None:
        return False, ["missing_eid_in_db"]

    reasons: List[str] = []
    for field in ("timestamp_utc", "actor_process", "action_type", "target_entity"):
        if _norm_field(claim.get(field)) != _norm_field(db_ev.get(field)):
            reasons.append(f"tuple_mismatch:{field}")

    vocab_err = _check_closed_vocabulary(str(claim.get("narrative_sentence") or ""), db_ev)
    if vocab_err:
        reasons.append(vocab_err)

    return (len(reasons) == 0), reasons


def verify_report(
    db_path: str,
    narration_doc: Dict[str, Any],
    cfg: PipelineConfig = config,
) -> Dict[str, Any]:
    """Verifies all claims in a Station 4A narration document against the full SQLite DB."""
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"SQLite database not found at '{db_path}'")

    conn = sqlite3.connect(db_path)
    try:
        total_claims = 0
        pre_supported = 0
        post_supported = 0
        temporal_contradictions = 0
        fallback_count = 0
        verified_subgraphs: List[Dict[str, Any]] = []

        for sg in narration_doc.get("subgraphs", []):
            verified_claims: List[Dict[str, Any]] = []
            prev_db_ts: Optional[str] = None

            for claim in sg.get("claims", []):
                total_claims += 1
                eid = str(claim.get("eid") or "")
                db_ev = _fetch_db_event(conn, eid)

                tuple_ok, reasons = verify_claim_tuple(claim, db_ev)

                # RCA_temporal: events closer than temporal_tolerance_ms are unordered (valid).
                # Flag only if current DB timestamp is strictly BEFORE previous DB timestamp
                # beyond tolerance_ms.
                temporal_ok = True
                if db_ev is not None and prev_db_ts is not None:
                    cur_ts = db_ev.get("timestamp_utc")
                    if is_before(cur_ts, prev_db_ts, cfg.temporal_tolerance_ms):
                        temporal_ok = False
                        temporal_contradictions += 1
                        reasons.append("temporal_contradiction")

                passed_pre = tuple_ok and temporal_ok
                if passed_pre:
                    pre_supported += 1
                    post_supported += 1
                    verified_sentence = claim.get("narrative_sentence")
                    used_fallback = False
                else:
                    fallback_count += 1
                    used_fallback = True
                    if db_ev is not None:
                        verified_sentence = format_m2_sentence(db_ev)
                        post_supported += 1
                    else:
                        verified_sentence = f"[REJECTED CLAIM: eid={eid} not found in SQLite DB]"

                if db_ev is not None:
                    prev_db_ts = db_ev.get("timestamp_utc")

                verified_claims.append(
                    {
                        "eid": eid,
                        "passed_pre_verification": passed_pre,
                        "used_fallback": used_fallback,
                        "failure_reasons": reasons,
                        "verified_sentence": verified_sentence,
                    }
                )

            verified_subgraphs.append(
                {
                    "subgraph_id": sg.get("subgraph_id"),
                    "rank": sg.get("rank"),
                    "summary_header": sg.get("summary_header"),
                    "claims": verified_claims,
                }
            )
    finally:
        conn.close()

    rca_pre = (pre_supported / total_claims) if total_claims else 1.0
    rca_post = (post_supported / total_claims) if total_claims else 1.0
    cmr_pre = 1.0 - rca_pre
    cmr_post = 1.0 - rca_post
    fallback_rate = (fallback_count / total_claims) if total_claims else 0.0

    return {
        "db": os.path.basename(db_path),
        "temporal_tolerance_ms": cfg.temporal_tolerance_ms,
        "metrics": {
            "total_claims": total_claims,
            "pre_supported_claims": pre_supported,
            "post_supported_claims": post_supported,
            "temporal_contradictions": temporal_contradictions,
            "fallback_count": fallback_count,
            "rca_pre": round(rca_pre, 4),
            "rca_post": round(rca_post, 4),
            "cmr_pre": round(cmr_pre, 4),
            "cmr_post": round(cmr_post, 4),
            "fallback_rate": round(fallback_rate, 4),
        },
        "subgraphs": verified_subgraphs,
    }


def execute_station4b(
    db_path: str,
    narration_json_path: str,
    out_json_path: str,
    cfg: PipelineConfig = config,
) -> Dict[str, Any]:
    with open(narration_json_path, "r", encoding="utf-8") as f:
        narration_doc = json.load(f)
    doc = verify_report(db_path, narration_doc, cfg=cfg)
    os.makedirs(os.path.dirname(os.path.abspath(out_json_path)), exist_ok=True)
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Station 4B: Deterministic Tuple & Temporal Verifier")
    ap.add_argument("--db", required=True)
    ap.add_argument("--narration", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    doc = execute_station4b(args.db, args.narration, args.out)
    print(json.dumps(doc["metrics"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
