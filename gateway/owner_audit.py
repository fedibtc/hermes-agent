"""Append-only owner audit log for multi-user gateway policy decisions."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from hermes_constants import get_hermes_home


_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|credential|authorization|cookie)", re.IGNORECASE)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_component(value: Any) -> str:
    raw = str(value or "unresolved").strip() or "unresolved"
    safe = _SAFE_COMPONENT_RE.sub("_", raw).strip("._")
    return safe[:80] or "unresolved"


def audit_log_path(subject_owner_id: str) -> Path:
    return get_hermes_home() / "owners" / _safe_component(subject_owner_id) / "audit.jsonl"


def _redact_value(key: str, value: Any) -> Any:
    if _SECRET_KEY_RE.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_value(str(child_key), child_value)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value[:20]]
    if isinstance(value, tuple):
        return [_redact_value(key, item) for item in value[:20]]
    if isinstance(value, str):
        if len(value) > 500:
            return value[:500] + "...[truncated]"
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:500]


def _sanitize_details(details: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(details, Mapping):
        return {}
    return {
        str(key): _redact_value(str(key), value)
        for key, value in details.items()
    }


def append_audit_event(
    *,
    subject_owner_id: str,
    event_type: str,
    requester: str = "",
    session_key: str = "",
    platform: str = "",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one owner audit event and return the recorded event.

    Audit failures must not break gateway operation, so callers may use this
    helper without wrapping it in their own exception handling.
    """

    owner_id = str(subject_owner_id or "unresolved").strip() or "unresolved"
    event = {
        "ts": _utcnow_iso(),
        "event_type": str(event_type or "event"),
        "subject_owner_id": owner_id,
        "requester": str(requester or ""),
        "session_key": str(session_key or ""),
        "platform": str(platform or ""),
        "details": _sanitize_details(details),
    }
    try:
        path = audit_log_path(owner_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        pass
    return event


def append_audit_event_for_context(
    context: Any,
    event_type: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    if context is None:
        return None
    requester = getattr(getattr(context, "requester", None), "key", "")
    return append_audit_event(
        subject_owner_id=getattr(context, "subject_owner_id", "") or "unresolved",
        event_type=event_type,
        requester=requester,
        session_key=getattr(context, "session_key", "") or "",
        platform=getattr(context, "platform", "") or "",
        details=details,
    )


def read_recent_audit_events(subject_owner_id: str, limit: int = 20) -> list[dict[str, Any]]:
    path = audit_log_path(subject_owner_id)
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    events: list[dict[str, Any]] = []
    for line in lines[-max(1, limit) * 3:]:
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events[-max(1, limit):]


__all__ = [
    "append_audit_event",
    "append_audit_event_for_context",
    "audit_log_path",
    "read_recent_audit_events",
]
