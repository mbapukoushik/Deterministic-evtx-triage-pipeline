"""Station 1: EVTX Ingestion & Evidence Integrity.

TEAM T12 – Digital Forensics and Incident Response (DFIR) Pipeline.
Role 1: Preservation & Ingestion.

Responsibilities:
- Read-only .evtx ingestion and SHA-256 hashing of original .evtx bytes on first read.
- Corrupted XML handling (M4) and EventRecordID sequence gap logging.
- Normalization of Sysmon events (1, 3, 8, 10, 11, 12, 13, 14, 22) and 1102/104 into the frozen 24-column SQLite events table.
- C1 incremental SHA-256 hash chain over raw XML records.
- External Ed25519 manifest.json + public key (.pub.pem) generation outside the SQLite database.
"""

import hashlib
import json
import logging
import os
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from Evtx.Evtx import Evtx

logger = logging.getLogger("station1_ingestor")

EVENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    record_index INTEGER PRIMARY KEY,
    eid TEXT UNIQUE,
    host TEXT,
    timestamp_utc TEXT,
    sysmon_event_id INTEGER,
    actor_guid TEXT,
    actor_process TEXT,
    action_type TEXT,
    target_guid TEXT,
    target_entity TEXT,
    command_line TEXT,
    canonical_command_line TEXT,
    logon_guid TEXT,
    user TEXT,
    raw_event_pointer TEXT,
    raw_event_hash TEXT,
    chain_hash TEXT,
    raw_xml TEXT,
    max_sigma_rule_id TEXT DEFAULT NULL,
    max_sigma_title TEXT DEFAULT NULL,
    max_sigma_level TEXT DEFAULT 'none',
    sigma_weight REAL DEFAULT 0.0,
    mitre_tactics TEXT DEFAULT NULL,
    is_malicious_gt INTEGER DEFAULT 0
);
"""


@dataclass
class IngestionSummary:
    """Summary of Station 1 EVTX ingestion and cryptographic manifest."""

    evtx_path: str
    db_path: str
    manifest_path: str
    public_key_path: str
    evtx_sha256: str
    total_records_parsed: int
    corrupted_records: int
    record_id_gaps: List[Tuple[int, int]] = field(default_factory=list)
    final_chain_hash: str = ""
    channels_seen: List[str] = field(default_factory=list)


def sha256_file_readonly(file_path: str) -> str:
    """Computes SHA-256 of the raw .evtx file opened read-only."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _normalize_timestamp_utc(raw_ts: Optional[str]) -> Optional[str]:
    """Normalizes Windows SystemTime strings to ISO-8601 UTC format."""
    if not raw_ts:
        return None
    ts = raw_ts.strip()
    if ts.endswith("Z"):
        ts_parse = ts[:-1] + "+00:00"
    else:
        ts_parse = ts
    try:
        # Handle 7-digit fractional seconds from Windows EVTX if present
        if "." in ts_parse:
            head, tail = ts_parse.split(".", 1)
            tz_part = ""
            for sep in ("+", "-"):
                if sep in tail:
                    frac, rest = tail.split(sep, 1)
                    tz_part = sep + rest
                    tail = frac
                    break
            tail = tail[:6].ljust(6, "0")
            ts_parse = f"{head}.{tail}{tz_part}"
        dt = datetime.fromisoformat(ts_parse)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return raw_ts


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_evtx_xml(raw_xml: str) -> Optional[Dict[str, Any]]:
    """Parses a single Windows Event XML string into normalized Sysmon/Audit fields."""
    root = ET.fromstring(raw_xml)
    system_el = None
    event_data_el = None
    for child in root:
        name = _strip_ns(child.tag)
        if name == "System":
            system_el = child
        elif name == "EventData":
            event_data_el = child

    if system_el is None:
        return None

    sys_fields: Dict[str, Any] = {}
    for child in system_el:
        name = _strip_ns(child.tag)
        if name == "TimeCreated":
            sys_fields["TimeCreated"] = child.attrib.get("SystemTime")
        else:
            sys_fields[name] = (child.text or "").strip()

    if "EventRecordID" not in sys_fields or "EventID" not in sys_fields:
        return None

    rec_id = int(sys_fields["EventRecordID"])
    event_id = int(sys_fields["EventID"])
    host = sys_fields.get("Computer") or None
    channel = sys_fields.get("Channel") or None
    timestamp_utc = _normalize_timestamp_utc(sys_fields.get("TimeCreated"))

    ed: Dict[str, Optional[str]] = {}
    if event_data_el is not None:
        for data_el in event_data_el:
            if _strip_ns(data_el.tag) == "Data":
                key = data_el.attrib.get("Name")
                if key:
                    val = data_el.text
                    ed[key] = val.strip() if isinstance(val, str) else val

    # Sysmon Actor/Target Normalization Mapping (Section 2.3)
    actor_guid: Optional[str] = None
    actor_process: Optional[str] = None
    action_type: str = f"EVENT_{event_id}"
    target_guid: Optional[str] = None
    target_entity: Optional[str] = None

    if event_id == 1:  # ProcessCreate
        action_type = "PROCESS_CREATE"
        actor_guid = ed.get("ParentProcessGuid")
        actor_process = ed.get("ParentImage")
        target_guid = ed.get("ProcessGuid")
        target_entity = ed.get("Image")
    elif event_id == 8:  # CreateRemoteThread
        action_type = "REMOTE_THREAD"
        actor_guid = ed.get("SourceProcessGuid")
        actor_process = ed.get("SourceImage")
        target_guid = ed.get("TargetProcessGuid")
        target_entity = ed.get("TargetImage")
    elif event_id == 10:  # ProcessAccess
        action_type = "PROCESS_ACCESS"
        actor_guid = ed.get("SourceProcessGuid")
        actor_process = ed.get("SourceImage")
        target_guid = ed.get("TargetProcessGuid")
        target_entity = ed.get("TargetImage")
    elif event_id == 3:  # NetworkConnect
        action_type = "NETWORK_CONNECT"
        actor_guid = ed.get("ProcessGuid")
        actor_process = ed.get("Image")
        target_entity = ed.get("DestinationIp")
    elif event_id == 11:  # FileCreate
        action_type = "FILE_CREATE"
        actor_guid = ed.get("ProcessGuid")
        actor_process = ed.get("Image")
        target_entity = ed.get("TargetFilename")
    elif event_id in (12, 13, 14):  # Registry
        action_type = "REGISTRY_EVENT"
        actor_guid = ed.get("ProcessGuid")
        actor_process = ed.get("Image")
        target_entity = ed.get("TargetObject")
    elif event_id == 22:  # DnsQuery
        action_type = "DNS_QUERY"
        actor_guid = ed.get("ProcessGuid")
        actor_process = ed.get("Image")
        target_entity = ed.get("QueryName")
    elif event_id in (1102, 104):  # LogClear
        action_type = "LOG_CLEARED"
        actor_guid = None
        actor_process = "SYSTEM_AUDIT"
        target_entity = "AuditLogCleared"
    else:
        # Other Sysmon/Windows events preserved deterministically
        actor_guid = ed.get("ProcessGuid")
        actor_process = ed.get("Image")
        target_entity = (
            ed.get("TargetFilename")
            or ed.get("TargetObject")
            or ed.get("TargetImage")
            or ed.get("ImageLoaded")
        )

    command_line = ed.get("CommandLine") or ed.get("Details")
    logon_guid = ed.get("LogonGuid")  # DISPLAY ONLY — NEVER USE FOR CORRELATION
    user = ed.get("User")

    return {
        "record_index": rec_id,
        "eid": f"rec_{rec_id}",
        "host": host,
        "channel": channel,
        "timestamp_utc": timestamp_utc,
        "sysmon_event_id": event_id,
        "actor_guid": actor_guid,
        "actor_process": actor_process,
        "action_type": action_type,
        "target_guid": target_guid,
        "target_entity": target_entity,
        "command_line": command_line,
        "logon_guid": logon_guid,
        "user": user,
        "raw_xml": raw_xml,
    }


def _sign_manifest_ed25519(
    manifest_payload: Dict[str, Any],
    manifest_path: str,
    public_key_path: str,
    private_key_path: Optional[str] = None,
) -> None:
    """Signs manifest payload with Ed25519 and writes manifest + public key outside SQLite."""
    if private_key_path and os.path.isfile(private_key_path):
        with open(private_key_path, "rb") as kf:
            priv_key = serialization.load_pem_private_key(kf.read(), password=None)
        if not isinstance(priv_key, Ed25519PrivateKey):
            raise TypeError("Provided key is not an Ed25519PrivateKey")
    else:
        priv_key = Ed25519PrivateKey.generate()

    pub_key: Ed25519PublicKey = priv_key.public_key()
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    os.makedirs(os.path.dirname(os.path.abspath(public_key_path)), exist_ok=True)
    with open(public_key_path, "wb") as pf:
        pf.write(pub_pem)

    canonical_bytes = json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature_hex = priv_key.sign(canonical_bytes).hex()

    signed_doc = {
        "manifest": manifest_payload,
        "signature_alg": "Ed25519",
        "signature_hex": signature_hex,
        "public_key_file": os.path.basename(public_key_path),
    }
    os.makedirs(os.path.dirname(os.path.abspath(manifest_path)), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(signed_doc, mf, indent=2)


def verify_manifest_ed25519(manifest_path: str, public_key_path: str) -> bool:
    """Verifies an external Ed25519-signed manifest.json against its external public key."""
    with open(manifest_path, "r", encoding="utf-8") as mf:
        signed_doc = json.load(mf)
    with open(public_key_path, "rb") as pf:
        pub_key = serialization.load_pem_public_key(pf.read())
    if not isinstance(pub_key, Ed25519PublicKey):
        return False
    canonical_bytes = json.dumps(
        signed_doc["manifest"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    sig_bytes = bytes.fromhex(signed_doc["signature_hex"])
    pub_key.verify(sig_bytes, canonical_bytes)
    return True


def ingest_evtx(
    evtx_path: str,
    db_path: str,
    manifest_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
    private_key_path: Optional[str] = None,
    overwrite_db: bool = True,
) -> IngestionSummary:
    """Ingests a raw .evtx file read-only into SQLite with C1 hash chain and Ed25519 manifest."""
    if not os.path.isfile(evtx_path):
        raise FileNotFoundError(f"EVTX file not found: '{evtx_path}'")

    db_dir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(db_dir, exist_ok=True)

    if manifest_path is None:
        stem = Path(db_path).stem
        manifest_path = os.path.join(db_dir, f"{stem}_manifest.json")
    if public_key_path is None:
        stem = Path(db_path).stem
        public_key_path = os.path.join(db_dir, f"{stem}_ed25519.pub.pem")

    # Hash original .evtx bytes on first read (read-only)
    evtx_sha256 = sha256_file_readonly(evtx_path)

    if overwrite_db and os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(EVENTS_TABLE_SQL)

    prev_chain = evtx_sha256
    seq_i = 0
    corrupted_count = 0
    prev_rec_id: Optional[int] = None
    record_id_gaps: List[Tuple[int, int]] = []
    channels_seen = set()

    with Evtx(evtx_path) as evtx_log:
        for record in evtx_log.records():
            try:
                raw_xml = record.xml()
                parsed = parse_evtx_xml(raw_xml)
                if parsed is None:
                    corrupted_count += 1
                    logger.warning("Skipping record with missing System/EventID/EventRecordID.")
                    continue
            except Exception as exc:
                corrupted_count += 1
                logger.warning("Corrupted XML/EVTX record encountered (M4): %s", exc)
                continue

            rec_id = parsed["record_index"]
            if prev_rec_id is not None and rec_id > prev_rec_id + 1:
                record_id_gaps.append((prev_rec_id, rec_id))
                logger.warning(
                    "EventRecordID gap detected: %d -> %d (missing %d records)",
                    prev_rec_id,
                    rec_id,
                    rec_id - prev_rec_id - 1,
                )
            prev_rec_id = rec_id

            if parsed.get("channel"):
                channels_seen.add(parsed["channel"])

            seq_i += 1
            raw_hash = hashlib.sha256(raw_xml.encode("utf-8")).hexdigest()
            chain_input = f"{seq_i}|{rec_id}|{prev_chain}|{raw_hash}".encode("ascii")
            chain_hash = hashlib.sha256(chain_input).hexdigest()
            prev_chain = chain_hash
            pointer = f"file_sha256={evtx_sha256};record_index={rec_id}"

            cur.execute(
                """
                INSERT OR REPLACE INTO events (
                    record_index, eid, host, timestamp_utc, sysmon_event_id,
                    actor_guid, actor_process, action_type, target_guid, target_entity,
                    command_line, canonical_command_line, logon_guid, user,
                    raw_event_pointer, raw_event_hash, chain_hash, raw_xml
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec_id,
                    parsed["eid"],
                    parsed["host"],
                    parsed["timestamp_utc"],
                    parsed["sysmon_event_id"],
                    parsed["actor_guid"],
                    parsed["actor_process"],
                    parsed["action_type"],
                    parsed["target_guid"],
                    parsed["target_entity"],
                    parsed["command_line"],
                    None,
                    parsed["logon_guid"],
                    parsed["user"],
                    pointer,
                    raw_hash,
                    chain_hash,
                    raw_xml,
                ),
            )

    conn.commit()
    conn.close()

    manifest_payload = {
        "evtx_filename": os.path.basename(evtx_path),
        "evtx_sha256": evtx_sha256,
        "db_filename": os.path.basename(db_path),
        "total_records_parsed": seq_i,
        "corrupted_records": corrupted_count,
        "record_id_gaps": record_id_gaps,
        "channels_seen": sorted(channels_seen),
        "final_chain_hash": prev_chain,
        "ingested_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _sign_manifest_ed25519(
        manifest_payload,
        manifest_path,
        public_key_path,
        private_key_path=private_key_path,
    )

    return IngestionSummary(
        evtx_path=evtx_path,
        db_path=db_path,
        manifest_path=manifest_path,
        public_key_path=public_key_path,
        evtx_sha256=evtx_sha256,
        total_records_parsed=seq_i,
        corrupted_records=corrupted_count,
        record_id_gaps=record_id_gaps,
        final_chain_hash=prev_chain,
        channels_seen=sorted(channels_seen),
    )
