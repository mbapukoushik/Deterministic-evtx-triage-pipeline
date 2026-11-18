"""Canonical event-time helpers shared by Stations 1, 3 and 4B.

Canonical event time (frozen, see README_SPEC.md §Canonical Event Time):
  events.timestamp_utc = System/TimeCreated/@SystemTime of the record, normalized to
  ISO-8601 UTC with millisecond precision ("YYYY-MM-DDTHH:MM:SS.mmmZ").

  - Present on every record of every channel (incl. Security 1102 / System 104,
    which have no Sysmon UtcTime field).
  - Equals Hayabusa's "Timestamp" when Hayabusa is run with -U.
  - Sysmon EventData/UtcTime is NOT used for ordering; it stays in raw_xml only.
    In the reference samples TimeCreated - UtcTime ranged 0..2048 ms.

Rules:
  - Canonical ordering is (timestamp_utc ASC, record_index ASC).
  - Timestamps are never compared for exact equality; use within_tolerance()
    and is_before() with PipelineConfig.temporal_tolerance_ms.
"""

from datetime import datetime, timezone
from typing import Optional

CANONICAL_ORDER_SQL = "ORDER BY timestamp_utc ASC, record_index ASC"


def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    """Parses canonical or Hayabusa-style UTC timestamps into aware datetimes."""
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    if s.endswith(" +00:00"):
        s = s[:-7] + "+00:00"
    s = s.replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if "." in s:
        head, tail = s.split(".", 1)
        tz = ""
        for sep in ("+", "-"):
            if sep in tail:
                frac, rest = tail.split(sep, 1)
                tz = sep + rest
                tail = frac
                break
        s = f"{head}.{tail[:6].ljust(6, '0')}{tz}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def delta_ms(a: Optional[str], b: Optional[str]) -> Optional[float]:
    """Returns (a - b) in milliseconds, or None if either side is unparseable."""
    da, db = parse_ts(a), parse_ts(b)
    if da is None or db is None:
        return None
    return (da - db).total_seconds() * 1000.0


def within_tolerance(a: Optional[str], b: Optional[str], tolerance_ms: float) -> bool:
    """True iff both timestamps parse and |a - b| <= tolerance_ms."""
    d = delta_ms(a, b)
    return d is not None and abs(d) <= tolerance_ms


def is_before(a: Optional[str], b: Optional[str], tolerance_ms: float) -> bool:
    """True iff a is strictly earlier than b by more than tolerance_ms."""
    d = delta_ms(a, b)
    return d is not None and d < -tolerance_ms


def temporal_relation(
    a_ts: Optional[str],
    b_ts: Optional[str],
    tolerance_ms: float,
) -> str:
    """Classifies the temporal relation between two timestamps.

    Events closer than tolerance_ms are treated as 'unordered' rather than
    strictly ordered (see README_SPEC.md).
    Returns: 'before' | 'after' | 'unordered' | 'unknown'
    """
    d = delta_ms(a_ts, b_ts)
    if d is None:
        return "unknown"
    if abs(d) <= tolerance_ms:
        return "unordered"
    return "before" if d < 0 else "after"
