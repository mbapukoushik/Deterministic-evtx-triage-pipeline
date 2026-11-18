"""Station 2: Hayabusa Integration and AST Command-Line Normalization.

TEAM T12 – Digital Forensics and Incident Response (DFIR) Pipeline.
Role 2: Myla Gangadhar Yadav.

Responsibilities:
1. Safe subprocess execution of Hayabusa without shell=True.
2. Line-by-line JSONL streaming and parsing with fault-tolerant malformed line handling.
3. Exact EventRecordID-to-record_index SQLite mapping (WHERE record_index = ?).
4. Sigma severity weighting (WEIGHT_MAP) with 'info' alias support and deterministic tie-breaking.
5. MITRE ATT&CK tactic merging and deduplication stored as JSON lists.
6. AST Command-Line Normalization (normalize_windows_cli) feature-flagged by use_ast_norm=False.
7. Strict preservation of raw forensic integrity fields and frozen 24-column SQLite schema.
"""

import base64
import json
import logging
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from config import PipelineConfig, config

logger = logging.getLogger("station2_hayabusa")

# Approved severity weight mapping table (canonical levels only)
WEIGHT_MAP: Dict[str, float] = {
    "none": 0.0,
    "informational": 0.1,
    "low": 0.3,
    "medium": 0.6,
    "high": 0.9,
    "critical": 1.0,
}

# Aliases emitted by Hayabusa (abbreviated output when -b is not passed) and Sigma variants.
LEVEL_ALIASES: Dict[str, str] = {
    "info": "informational",
    "informational": "informational",
    "med": "medium",
    "crit": "critical",
}


def normalize_severity(raw_level: Optional[str]) -> Tuple[str, float]:
    """Normalizes severity strings (case/whitespace-insensitive, Hayabusa aliases supported).

    Unknown, empty or missing levels map to ("none", 0.0).

    Returns:
        (normalized_level_str, numerical_weight)
    """
    if raw_level is None or not isinstance(raw_level, str):
        return ("none", 0.0)

    clean = raw_level.strip().lower()
    clean = LEVEL_ALIASES.get(clean, clean)
    if clean not in WEIGHT_MAP:
        return ("none", 0.0)
    return (clean, WEIGHT_MAP[clean])


def extract_tactics(alert: Dict[str, Any]) -> List[str]:
    """Extracts MITRE ATT&CK tactics from a Hayabusa/Sigma alert.

    Only tactic keys are read ("MitreTactics", "Tactics", "tactics"). "MitreTags" holds
    technique IDs (e.g. T1558) and is deliberately NOT treated as tactics.
    Missing, null or malformed keys yield an empty list.
    """
    raw = None
    for key in ("MitreTactics", "Tactics", "tactics"):
        if alert.get(key):
            raw = alert[key]
            break
    if raw is None:
        return []
    if isinstance(raw, str):
        items = raw.split(",")
    elif isinstance(raw, list):
        items = [str(t) for t in raw if t is not None]
    else:
        return []
    return sorted({t.strip().lower() for t in items if t.strip()})


def normalize_windows_cli(cmd: Optional[str]) -> Optional[str]:
    """De-obfuscates Windows command-line strings using deterministic AST transformations.

    Transformations performed:
    1. Base64 UTF-16LE decoding for -EncodedCommand, -enc, -e, -ec flags, with recursive normalization.
    2. Removal of Windows CMD caret escapes (^).
    3. Removal of dummy empty double quotes ("").
    4. Removal of PowerShell backtick escapes (`).

    Safety and forensic preservation:
    - Returns None if cmd is None.
    - Preserves original argument if Base64 decoding fails.
    - Never mutates input strings in place.
    """
    if cmd is None:
        return None
    if not isinstance(cmd, str) or not cmd:
        return cmd

    # 1. Base64 UTF-16LE Decoding (-EncodedCommand, -enc, -e, -ec)
    def _decode_b64(match: re.Match) -> str:
        flag = match.group(1)
        sep = match.group(2)
        b64_candidate = match.group(3)

        try:
            # Re-pad if necessary
            padded = b64_candidate + "=" * ((4 - len(b64_candidate) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded_text = decoded_bytes.decode("utf-16le")
            # Recursively normalize decoded content
            normalized_decoded = normalize_windows_cli(decoded_text)
            return f"{flag}{sep}[DECODED_B64: {normalized_decoded}]"
        except Exception:
            # Preserve original encoded argument if invalid Base64 or non-UTF16
            return match.group(0)

    # Regex matches -EncodedCommand, -enc, -e, -ec followed by whitespace or separator and Base64 string
    enc_pattern = re.compile(
        r"(?i)([-/](?:encodedcommand|enc|ec|e))(\s+|[:=])([A-Za-z0-9+/=]{4,})",
    )
    result = enc_pattern.sub(_decode_b64, cmd)

    # 2. CMD caret escapes (e.g., w^h^o^a^m^i -> whoami)
    result = re.sub(r"\^([^\r\n])", r"\1", result)

    # 3. Dummy empty double quotes (e.g., w""hoami -> whoami, pow""ershell -> powershell)
    result = re.sub(r'""', "", result)

    # 4. PowerShell backticks (e.g., i`e`x -> iex)
    result = re.sub(r"`([^\r\n])", r"\1", result)

    return result


@dataclass
class SigmaAlertAggregate:
    """Aggregated Sigma detections for a single EventRecordID (scoped by Channel + Computer)."""

    record_index: int
    max_rule_id: Optional[str] = None
    max_title: Optional[str] = None
    max_level: str = "none"
    max_weight: float = 0.0
    tactics: List[str] = field(default_factory=list)
    channel: Optional[str] = None
    computer: Optional[str] = None
    evtx_file: Optional[str] = None


_CHANNEL_ABBREV_MAP: Dict[str, str] = {
    "sysmon": "microsoft-windows-sysmon/operational",
    "security": "security",
    "system": "system",
    "application": "application",
    "pwsh": "microsoft-windows-powershell/operational",
    "powershell": "windows powershell",
}


def _normalize_channel(channel: Optional[str]) -> Optional[str]:
    if not channel or not isinstance(channel, str):
        return None
    low = channel.strip().lower()
    return _CHANNEL_ABBREV_MAP.get(low, low)


def _extract_channel_from_xml(raw_xml: Optional[str]) -> Optional[str]:
    if not raw_xml:
        return None
    m = re.search(r"<Channel>([^<]+)</Channel>", raw_xml)
    return _normalize_channel(m.group(1)) if m else None


def run_hayabusa(
    hayabusa_bin: str,
    evtx_path: str,
    output_jsonl: str,
    extra_args: Optional[List[str]] = None,
) -> Tuple[int, str, str]:
    """Executes the Hayabusa v4 binary using Python subprocess with safe argument handling.

    Uses dfir-timeline with -U (UTC), -t jsonl, -p super-verbose, -b (full channel names),
    and never uses shell=True.

    Returns:
        (returncode, stdout, stderr)
    """
    if not os.path.isfile(hayabusa_bin):
        raise FileNotFoundError(f"Hayabusa binary not found at '{hayabusa_bin}'")
    if not os.path.exists(evtx_path):
        raise FileNotFoundError(f"Target EVTX input path not found at '{evtx_path}'")

    os.makedirs(os.path.dirname(os.path.abspath(output_jsonl)), exist_ok=True)

    cmd = [
        hayabusa_bin,
        "dfir-timeline",
        "-f",
        evtx_path,
        "-o",
        output_jsonl,
        "-t",
        "jsonl",
        "-p",
        "super-verbose",
        "-U",
        "-b",
        "-w",
        "-C",
        "-q",
        "-N",
    ]
    bin_dir = os.path.dirname(os.path.abspath(hayabusa_bin))
    rules_dir = os.path.join(bin_dir, "rules")
    rules_cfg = os.path.join(rules_dir, "config")
    if os.path.isdir(rules_dir):
        cmd.extend(["-r", rules_dir])
    if os.path.isdir(rules_cfg):
        cmd.extend(["-c", rules_cfg])
    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_hayabusa_jsonl(
    jsonl_path: str,
) -> Tuple[Dict[int, SigmaAlertAggregate], int, int, str]:
    """Parses a Hayabusa JSONL alert file line by line.

    Handles malformed lines safely without crashing. Extracts the EventRecordID field.
    Deduplicates and merges MITRE tactics and tracks highest-severity Sigma alert.

    Returns:
        (aggregates_by_record_index, total_valid_alerts, malformed_lines_count, discovered_record_field)
    """
    if not os.path.isfile(jsonl_path):
        raise FileNotFoundError(f"Hayabusa JSONL output file not found at '{jsonl_path}'")

    aggregates: Dict[int, SigmaAlertAggregate] = {}
    malformed_count = 0
    total_valid = 0
    discovered_field = "EventRecordID"

    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            try:
                alert = json.loads(line_str)
            except Exception as e:
                malformed_count += 1
                logger.warning("Malformed JSON on line %d of '%s': %s", line_num, jsonl_path, e)
                continue

            if not isinstance(alert, dict):
                malformed_count += 1
                continue

            # Identify EventRecordID field
            rec_id = None
            for candidate in ("EventRecordID", "RecordID", "event_record_id"):
                if candidate in alert:
                    discovered_field = candidate
                    try:
                        rec_id = int(alert[candidate])
                        break
                    except (ValueError, TypeError):
                        pass

            if rec_id is None:
                # Missing or invalid EventRecordID
                continue

            total_valid += 1

            # Extract rule details
            rule_id = alert.get("RuleID") or alert.get("rule_id")
            title = alert.get("RuleTitle") or alert.get("title") or alert.get("RuleName")
            raw_level = alert.get("Level") or alert.get("level") or alert.get("Severity")
            channel = _normalize_channel(alert.get("Channel") or alert.get("channel"))
            computer_raw = alert.get("Computer") or alert.get("computer")
            computer = computer_raw.strip().lower() if isinstance(computer_raw, str) and computer_raw.strip() else None
            evtx_file = alert.get("EvtxFile") or alert.get("evtx_file")

            norm_level, weight = normalize_severity(raw_level)

            # Extract tactics (MitreTactics/Tactics only; MitreTags are technique IDs)
            parsed_tactics = extract_tactics(alert)

            if rec_id not in aggregates:
                aggregates[rec_id] = SigmaAlertAggregate(
                    record_index=rec_id,
                    max_rule_id=rule_id,
                    max_title=title,
                    max_level=norm_level,
                    max_weight=weight,
                    tactics=sorted(list(set(parsed_tactics))),
                    channel=channel,
                    computer=computer,
                    evtx_file=evtx_file,
                )
            else:
                existing = aggregates[rec_id]
                if existing.channel is None and channel is not None:
                    existing.channel = channel
                if existing.computer is None and computer is not None:
                    existing.computer = computer
                if existing.evtx_file is None and evtx_file is not None:
                    existing.evtx_file = evtx_file

                # Update max sigma rule if new alert is higher weight
                # Deterministic tie-breaking: if weights are equal, lower RuleID wins
                if weight > existing.max_weight:
                    existing.max_rule_id = rule_id
                    existing.max_title = title
                    existing.max_level = norm_level
                    existing.max_weight = weight
                elif weight == existing.max_weight and rule_id:
                    if existing.max_rule_id is None or str(rule_id) < str(existing.max_rule_id):
                        existing.max_rule_id = rule_id
                        existing.max_title = title
                        existing.max_level = norm_level

                # Merge tactics
                merged = set(existing.tactics).union(parsed_tactics)
                existing.tactics = sorted(list(merged))

    return aggregates, total_valid, malformed_count, discovered_field


def enrich_sqlite_database(
    db_path: str,
    aggregates: Dict[int, SigmaAlertAggregate],
    cfg: PipelineConfig = config,
) -> Dict[str, Any]:
    """Enriches the frozen SQLite events table with Sigma alerts and optional AST normalization.

    Strict Invariants Enforced:
    1. Join anchor is strictly 'WHERE record_index = ?' (matching EventRecordID).
    2. Never modifies record_index, raw_xml, raw_event_hash, chain_hash, or raw_event_pointer.
    3. Never modifies or overwrites the original command_line.
    4. Populates canonical_command_line ONLY when cfg.use_ast_norm is True.
    5. Leaves canonical_command_line as NULL/untouched when cfg.use_ast_norm is False.
    6. Never accesses or modifies is_malicious_gt.
    7. Never uses logon_guid for correlation.

    Returns:
        Summary statistics dictionary.
    """
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"SQLite database not found at '{db_path}'")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Query existing records to update
    cur.execute("SELECT record_index, host, command_line, raw_xml FROM events")
    rows = cur.fetchall()

    updated_count = 0
    matched_alerts_count = 0
    primary_matched_count = 0
    fallback_matched_count = 0
    ast_normalized_count = 0

    for rec_idx, host, raw_cli, raw_xml in rows:
        # Determine Sigma alert fields using primary (Channel, Computer, RecordID) join
        alert = aggregates.get(rec_idx)
        matched_alert = None
        if alert is not None:
            row_channel = _extract_channel_from_xml(raw_xml)
            row_computer = host.strip().lower() if isinstance(host, str) and host.strip() else None
            if alert.channel and alert.computer and row_channel and row_computer:
                if alert.channel == row_channel and alert.computer == row_computer:
                    matched_alert = alert
                    primary_matched_count += 1
                else:
                    logger.warning(
                        "Composite key mismatch for RecordID=%d: alert=(%s, %s) vs db=(%s, %s); skipping.",
                        rec_idx,
                        alert.channel,
                        alert.computer,
                        row_channel,
                        row_computer,
                    )
            else:
                logger.warning(
                    "Falling back to RecordID-only join for RecordID=%d (missing Channel/Computer in alert or DB).",
                    rec_idx,
                )
                matched_alert = alert
                fallback_matched_count += 1

        if matched_alert is not None:
            matched_alerts_count += 1
            max_rule_id = matched_alert.max_rule_id
            max_title = matched_alert.max_title
            max_level = matched_alert.max_level
            sigma_weight = matched_alert.max_weight
            tactics_json = json.dumps(matched_alert.tactics) if matched_alert.tactics else None
        else:
            # Preserve approved defaults when no alert matches
            max_rule_id = None
            max_title = None
            max_level = "none"
            sigma_weight = 0.0
            tactics_json = None

        # Determine canonical_command_line
        if cfg.use_ast_norm:
            canonical_cli = normalize_windows_cli(raw_cli)
            if canonical_cli != raw_cli:
                ast_normalized_count += 1
        else:
            # When use_ast_norm is False, canonical_command_line must remain NULL
            canonical_cli = None

        # Parameterized update matching strictly record_index
        cur.execute(
            """
            UPDATE events
            SET max_sigma_rule_id = ?,
                max_sigma_title = ?,
                max_sigma_level = ?,
                sigma_weight = ?,
                mitre_tactics = ?,
                canonical_command_line = ?
            WHERE record_index = ?
            """,
            (
                max_rule_id,
                max_title,
                max_level,
                sigma_weight,
                tactics_json,
                canonical_cli,
                rec_idx,
            ),
        )
        updated_count += 1

    conn.commit()
    conn.close()

    unique_alert_records = len(aggregates)
    join_hit_rate = (
        matched_alerts_count / unique_alert_records if unique_alert_records > 0 else 0.0
    )

    return {
        "total_records_processed": updated_count,
        "matched_sigma_records": matched_alerts_count,
        "primary_matched_records": primary_matched_count,
        "fallback_matched_records": fallback_matched_count,
        "unique_alert_records": unique_alert_records,
        "join_hit_rate": round(join_hit_rate, 4),
        "unmatched_sigma_records": updated_count - matched_alerts_count,
        "ast_normalized_count": ast_normalized_count,
        "use_ast_norm": cfg.use_ast_norm,
    }


def execute_station2(
    db_path: str,
    jsonl_path: str,
    cfg: PipelineConfig = config,
) -> Dict[str, Any]:
    """Orchestrates Station 2 processing on an existing database and Hayabusa JSONL output."""
    aggregates, total_valid, malformed_count, rec_field = parse_hayabusa_jsonl(jsonl_path)
    enrich_results = enrich_sqlite_database(db_path, aggregates, cfg)
    enrich_results["total_valid_alerts"] = total_valid
    enrich_results["malformed_jsonl_lines"] = malformed_count
    enrich_results["discovered_record_field"] = rec_field
    return enrich_results
