# Deterministic Windows Sysmon/EVTX Forensic Triage Pipeline with Tuple-Verified Reporting

**Team:** TEAM T12 – Digital Forensics and Incident Response (DFIR) Pipeline  
**Target Environment:** Windows 10/11 x64, Python 3.10  

## Overview
This repository contains the deterministic, tamper-evident triage pipeline for Windows Sysmon and EVTX event logs. The pipeline enforces cryptographic evidence integrity, exact index-to-rule mapping via Hayabusa, process lineage and persistence graph reconstruction, and deterministic tuple verification of LLM incident narration.

For authoritative technical requirements, see `README_TEAM_HANDOFF.md`.

## Pipeline Architecture
1. **Station 1 (`station1_ingestor.py`)**: EVTX Ingestion & Cryptographic Evidence Integrity (SHA-256 + Ed25519).
2. **Station 2 (`station2_hayabusa.py`)**: Hayabusa Alert Ingestion, 1:1 Record Mapping & AST CLI Normalization.
3. **Station 3 (`station3_graph_scorer.py`)**: Lineage Tree Reconstruction & Subgraph Priority Scoring.
4. **Station 4A (`station4a_narrator.py`)**: M2 Deterministic Narration & Local Ollama Reporting.
5. **Station 4B (`station4b_verifier_ui.py`)**: Tuple Verification, M2 Fallback & Streamlit Review UI.

## Setup
```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Hayabusa Tool Specification & Status
- **Official Source**: [Yamato Security Hayabusa](https://github.com/Yamato-Security/hayabusa)
- **Target Release Version**: `v2.17.0` (x86_64-pc-windows-msvc)
- **Official Rules Repository**: [Yamato Security Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules)
- **Host Installation Status**: Not installed on host system PATH or local workspace.
- **Station 2 Wrapper**: `run_hayabusa()` in `station2_hayabusa.py` executes `hayabusa.exe json-timeline -f <evtx> -o <jsonl> --output-jsonl --quiet` using safe subprocess execution (`shell=False`).
- **Offline / Test Fixture**: In offline environments or test mode, Station 2 consumes generated JSONL alert streams directly (`data/hayabusa_out/mock_hayabusa.jsonl`).

## Project Implementation Status
- **Phase 1 (Project Foundation & Setup):** Completed.
- **Phase 2 (Station 2 Hayabusa Integration & AST Normalization):** Completed and mock-data tests verified (28/28 tests passing).

### Pending Validation
- Hayabusa executable installation and version verification.
- Exact Hayabusa rules repository commit SHA.
- Actual Hayabusa JSONL output verification with live binary.
- Real Windows EVTX processing.



