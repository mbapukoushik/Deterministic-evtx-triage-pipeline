# Deterministic Windows Sysmon/EVTX Forensic Triage Pipeline with Tuple-Verified Reporting

**Team:** TEAM T12 – Digital Forensics and Incident Response (DFIR) Pipeline  
**Target Environment:** Windows 10/11 x64, Python 3.11.9  

## Overview
This repository contains the deterministic, integrity-checked triage pipeline for Windows Sysmon and EVTX event logs. The pipeline enforces cryptographic evidence integrity checks, exact index-to-rule mapping via Hayabusa, process lineage and persistence graph reconstruction, and deterministic tuple verification of incident narration.

Technical requirements: `README_TEAM_HANDOFF.md` (master spec) and `README_SPEC.md` (frozen engineering decisions: join key, canonical time, severity mapping, Station 3 & 4 rules).

## Pipeline Architecture
1. **Station 1 (`station1_ingestor.py`)**: Read-only EVTX ingestion, SHA-256 of original file, C1 hash chain, external Ed25519 manifest integrity check.
2. **Station 2 (`station2_hayabusa.py`)**: Hayabusa v4 alert ingestion, `(Channel, Computer, RecordID)` join, AST CLI normalization.
3. **Station 3 (`station3_graph_scorer.py`)**: Provenance DAG (lineage + persistence bridges) and subgraph priority scoring.
4. **Station 4A (`station4a_narrator.py`)**: M2 deterministic narration (`{shown} of {total} events shown`, LLM mode deferred).
5. **Station 4B (`station4b_verifier_ui.py`)**: Deterministic SQLite tuple + temporal verifier with automatic M2 fallback.

## Setup
```powershell
python -m venv .venv            # Python 3.11.9
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt  # exact pins; full lock in requirements.lock
python -m pytest -q
```

Hayabusa v4.4.0 and its rules go in `tools/hayabusa/` (git-ignored). Versions and hashes: `docs/setup_log.md`.

## Status
- Phase 1–2: complete.
- Station 1: complete; verified on 3 public Sysmon samples (EVTX-ATTACK-SAMPLES).
- Station 2: join key fixed to `(Channel, Computer, RecordID)`, `-U` UTC, warning on fallback; real-data fixture tests.
- Station 3: logic implemented and unit-tested; no evaluation numbers until own-lab traces exist.
- Station 4A & 4B: deterministic M2 template narrator + SQLite tuple & temporal verifier with M2 fallback implemented and tested on real-data fixtures.
- Lab Scripts: `scripts/setup_lab.ps1` and `scripts/run_scenario.ps1` added for Windows VM trace collection.
