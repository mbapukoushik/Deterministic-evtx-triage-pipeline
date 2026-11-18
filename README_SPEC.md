# TEAM T12 DFIR Pipeline — Engineering Spec Addendum (frozen decisions)

This file records decisions made while wiring the pipeline to **real** Hayabusa output.
It extends (does not replace) the frozen schema and guardrails in `README_TEAM_HANDOFF.md`.

## 1. Environment

| Item | Value |
| --- | --- |
| Python | **3.11.9** (Windows x64). The original plan said 3.10; 3.10 is not installed on the build host. |
| Direct deps | `requirements.txt` (exact pins) |
| Full lock | `requirements.lock` (`pip freeze --all`) |
| Hayabusa | v4.4.0 `hayabusa-4.4.0-win-x64.zip`, SHA-256 verified against GitHub release digest — see `docs/setup_log.md` |
| Hayabusa rules | commit `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846` |

Hayabusa v4 renamed `json-timeline` to `dfir-timeline`. Station 2 runs:

```
hayabusa dfir-timeline -f <evtx> -o <jsonl> -t jsonl -p super-verbose -U -b -w -C -q -N -r <rules> -c <rules/config>
```

`-U` = UTC timestamps; `-b` = no abbreviations (full channel names and level names).

## 2. Hayabusa ↔ SQLite join key

- Record IDs are unique only per log file, so the **primary key is `(Channel, Computer, RecordID)`**.
  - Hayabusa: `Channel`, `Computer`, `RecordID` (top-level keys, confirmed on real output).
  - SQLite: `Channel` parsed from `raw_xml`, `host`, `record_index`.
  - Channel and Computer are compared case-insensitively; Hayabusa abbreviations (`Sysmon`, `Sec`, …) are mapped if `-b` is not used.
- If the alert or the row lacks Channel/Computer, Station 2 joins on RecordID only **and logs a WARNING** (`fallback_matched_records` counter).
- If Channel or Computer disagree, the alert is **not joined** and a WARNING is logged.
- `join_hit_rate` = joined unique alert RecordIDs / unique alert RecordIDs.
- Note: in `super-verbose` mode Hayabusa emits an informational rule (`Proc Exec`, `Net Conn`, …) for nearly every Sysmon event, so join hit rate ≈ coverage of events, and almost every event gets `sigma_weight ≥ 0.1`.

## 3. Canonical event time

- `events.timestamp_utc` = `System/TimeCreated/@SystemTime`, normalized to ISO-8601 UTC, millisecond precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
  - Present for every channel, including Security 1102 / System 104 (no Sysmon `UtcTime`).
  - Equals Hayabusa `Timestamp` when run with `-U` (verified: Δ = 0 ms on real rows).
- Sysmon `EventData/UtcTime` is **not** used for ordering or verification; it stays in `raw_xml`.
  Observed `TimeCreated − UtcTime` on the reference samples: 0–2048 ms.
- Canonical ordering everywhere (Station 3, 4A, 4B, RCA_temporal): **`(timestamp_utc ASC, record_index ASC)`** (`event_time.CANONICAL_ORDER_SQL`).
- Timestamps are **never compared for exact equality**. Use `event_time.within_tolerance()` / `is_before()` / `temporal_relation()` with `PipelineConfig.temporal_tolerance_ms` (default 2500 ms, chosen above the observed 2048 ms skew).
- **Unordered Semantics & Limitation:** Events closer than `temporal_tolerance_ms` are treated as `"unordered"` in the narrator (`station4a_narrator.py`) and verifier (`station4b_verifier_ui.py`, never flagged as a temporal contradiction); within a single channel, events are ordered deterministically by `RecordID`. This `2500 ms` tolerance window is a documented limitation: sub-2.5s cross-channel causal inversions cannot be distinguished from clock/ingestion skew.

## 4. Severity and MITRE extraction

- `WEIGHT_MAP`: none 0.0, informational 0.1, low 0.3, medium 0.6, high 0.9, critical 1.0.
- Aliases: `info`→informational, `med`→medium, `crit`→critical. Unknown/empty/missing → `none` (0.0).
- Tactics are read only from `MitreTactics` (or legacy `Tactics`). `MitreTags` holds technique IDs (e.g. `T1558`) and is **not** a tactic source. Missing/null keys → `[]`.
- Tactic strings are stored lower-cased as Hayabusa emits them (e.g. `credaccess`, `latmov`, `c2`, `stealth`).

## 5. Station 3 (graph + scoring)

- One node per event; edges only go forward in canonical order ⇒ DAG.
- `PROCESS_LINEAGE`: (a) `PROCESS_CREATE` with `target_guid = P` → every later event with `actor_guid = P`; (b) chronological chain of events with the same `actor_guid`. Both are skipped when P's image basename is in `benign_roots`.
- `FILE_BRIDGE` / `REGISTRY_BRIDGE` as in the handoff spec; window `pseudo_edge_window_sec` (300 s).
- Never correlated on: `logon_guid`, LogonId, ProcessId, user, host.
- Scores: `S_norm` (default) / unnormalized sum (`use_size_norm=False`). `use_morse_decay` multiplies weight by `0.5^d`, d = lineage hops from the nearest benign-root-actor event (0 if none).
- Prompt events per subgraph: top `max_events_per_prompt` (25) by `sigma_weight` (ties by canonical order), emitted chronologically; `all_eids` keeps the full list.
- Real public samples are used for **logic tests only**. No Station 3 numbers are reported until own-lab traces exist.

## 6. Integrity Check, Station 4 & Evaluation Baselines

- **Integrity Check (not "tamper-evident" yet):** Station 1 supports an external persistent Ed25519 private key (`private_key_path` outside the repo). Until a persistent keypair is provisioned, the public key is documented, and manifest hashes are anchored in a git tag, docs refer to this as an **integrity check**.
- **Morse Decay:** Left `False` by default; decay direction (`0.5^d` from benign root vs toward benign root) remains an open spec question.
- **Station 4A / 4B:** `station4a_narrator.py` emits deterministic `M2` narration stating `"{shown} of {total} events shown"` (deterministic tie-break by `RecordID`). `station4b_verifier_ui.py` verifies claims against the full SQLite DB, treats events within `temporal_tolerance_ms` as unordered, and falls back to `M2` on any tuple, temporal, or closed-vocabulary failure.
- **Future `evaluate.py` Baselines:**
  1. Rank subgraphs by **max Hayabusa `Level` only** (ignoring size/tactic diversity).
  2. Ablate `informational` weight **`0.0` vs `0.1`** (since `super-verbose` attaches an informational rule to nearly every Sysmon event).
- **Open Items:** Sensitivity sweep for `pseudo_edge_window_sec` (300 s) and `benign_roots` on own-lab traces.
