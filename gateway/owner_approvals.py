"""Owner approval request storage and execution helpers.

This store is separate from the existing dangerous-command approval queue.
Dangerous-command approvals unblock a waiting tool thread; owner approvals are
durable requests for owner-mediated resource actions such as calendar writes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
import contextvars
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

# fcntl is Unix-only; on Windows fall back to msvcrt for file locking.
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
try:
    import msvcrt
except ImportError:  # pragma: no cover - non-Windows
    msvcrt = None

from hermes_constants import get_hermes_home


APPROVAL_ID_PREFIX = "apr_"
_current_approval_notifier: contextvars.ContextVar[Callable[[Mapping[str, Any]], None] | None] = (
    contextvars.ContextVar("gateway_owner_approval_notifier", default=None)
)


def approval_store_path() -> Path:
    return get_hermes_home() / "owner_approvals" / "requests.json"


def calendar_events_path() -> Path:
    return get_hermes_home() / "owner_approvals" / "calendar_events.json"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _atomic_write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


def read_approval_store(path: Path | None = None) -> dict[str, Any]:
    path = path or approval_store_path()
    if not path.exists():
        return {"requests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"requests": []}
    if isinstance(data, dict) and isinstance(data.get("requests"), list):
        return data
    if isinstance(data, list):
        return {"requests": data}
    return {"requests": []}


def write_approval_store(data: Mapping[str, Any], path: Path | None = None) -> None:
    _atomic_write_json(path or approval_store_path(), data)


@contextmanager
def _approval_store_lock(path: Path | None = None):
    """Hold an exclusive cross-process lock for read-modify-write safety.

    Creating, approving, denying, and expiring requests are all
    read-append/modify-write sequences against a single JSON file. Without a
    lock, two gateway threads or processes can read the same snapshot and the
    later atomic write silently drops the earlier change (e.g. a freshly
    created approval request disappears before the owner sees it). A separate
    ``.lock`` file is used so the store itself can still be replaced atomically
    via :func:`os.replace`.
    """

    store_path = path or approval_store_path()
    lock_path = store_path.with_suffix(store_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    if fcntl is None and msvcrt is None:
        yield
        return

    fd = open(lock_path, "a+", encoding="utf-8")
    try:
        if fcntl:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            fd.seek(0)
            msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        if fcntl:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (OSError, IOError):
                pass
        elif msvcrt:
            try:
                fd.seek(0)
                msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
            except (OSError, IOError):
                pass
        fd.close()


def _audit_request_event(event_type: str, request: Mapping[str, Any], details: Mapping[str, Any] | None = None) -> None:
    try:
        from gateway.owner_audit import append_audit_event

        requester_context = request.get("requester_context")
        requester_context = requester_context if isinstance(requester_context, Mapping) else {}
        event_details = {
            "approval_request_id": request.get("id"),
            "action_type": request.get("action_type"),
            "status": request.get("status"),
            "risk": request.get("risk"),
            "summary": request.get("summary"),
        }
        if details:
            event_details.update(dict(details))
        append_audit_event(
            subject_owner_id=str(request.get("subject_owner_id") or "unresolved"),
            event_type=event_type,
            requester=str(request.get("requester") or ""),
            session_key=str(requester_context.get("session_key") or ""),
            platform=str(requester_context.get("platform") or ""),
            details=event_details,
        )
    except Exception:
        pass


def set_current_approval_notifier(
    callback: Callable[[Mapping[str, Any]], None] | None,
) -> contextvars.Token:
    """Bind a best-effort owner approval notification callback."""

    return _current_approval_notifier.set(callback)


def reset_current_approval_notifier(token: contextvars.Token) -> None:
    """Restore the previous approval notification callback."""

    _current_approval_notifier.reset(token)


def _notify_approval_request(request: Mapping[str, Any]) -> None:
    callback = _current_approval_notifier.get()
    if callback is None:
        return
    try:
        callback(dict(request))
    except Exception:
        pass


def _read_calendar_events(path: Path | None = None) -> dict[str, Any]:
    path = path or calendar_events_path()
    if not path.exists():
        return {"events": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"events": []}
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        return data
    if isinstance(data, list):
        return {"events": data}
    return {"events": []}


def _write_calendar_events(data: Mapping[str, Any], path: Path | None = None) -> None:
    _atomic_write_json(path or calendar_events_path(), data)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _load_config() -> Mapping[str, Any]:
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
        return cfg if isinstance(cfg, Mapping) else {}
    except Exception:
        return {}


def _calendar_external_config(subject_owner_id: str) -> Mapping[str, Any]:
    cfg = _load_config()
    owner = _as_mapping(_as_mapping(cfg.get("owners")).get(subject_owner_id))
    calendar = _as_mapping(owner.get("calendar"))
    if not calendar:
        calendar = _as_mapping(owner.get("calendar_provider"))
    if not calendar:
        calendar = _as_mapping(cfg.get("calendar"))
    if not calendar:
        return {}

    enabled = calendar.get("external_commit")
    if enabled is None:
        enabled = calendar.get("external_writes")
    if enabled is None:
        enabled = calendar.get("commit_external")
    if not bool(enabled):
        return {}

    provider = str(calendar.get("provider") or "").strip().lower()
    if provider not in {"google_workspace", "google", "gws"}:
        return {
            "enabled": True,
            "provider": provider or "unknown",
            "error": f"Unsupported external calendar provider '{provider or 'unknown'}'.",
        }
    return {
        "enabled": True,
        "provider": "google_workspace",
        "calendar_id": str(calendar.get("calendar_id") or calendar.get("calendar") or "primary"),
    }


def _google_workspace_script_path() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "skills"
        / "productivity"
        / "google-workspace"
        / "scripts"
        / "google_api.py"
    )


def _create_google_workspace_calendar_event(
    payload: Mapping[str, Any],
    provider_config: Mapping[str, Any],
) -> dict[str, Any]:
    script = _google_workspace_script_path()
    if not script.exists():
        return {
            "success": False,
            "provider": "google_workspace",
            "error": f"Google Workspace calendar helper not found at {script}.",
        }

    summary = str(payload.get("summary") or "").strip()
    start = str(payload.get("start") or "").strip()
    end = str(payload.get("end") or "").strip()
    if not summary or not start or not end:
        return {
            "success": False,
            "provider": "google_workspace",
            "error": "summary, start, and end are required for external calendar creation.",
        }

    cmd = [
        sys.executable,
        str(script),
        "calendar",
        "create",
        "--summary",
        summary,
        "--start",
        start,
        "--end",
        end,
        "--calendar",
        str(provider_config.get("calendar_id") or "primary"),
    ]
    for arg_name, payload_key in (("--location", "location"), ("--description", "description")):
        value = str(payload.get(payload_key) or "").strip()
        if value:
            cmd.extend([arg_name, value])
    attendees = payload.get("attendees")
    if isinstance(attendees, list):
        attendee_text = ",".join(str(item).strip() for item in attendees if str(item).strip())
        if attendee_text:
            cmd.extend(["--attendees", attendee_text])

    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        return {"success": False, "provider": "google_workspace", "error": str(exc)}

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        return {"success": False, "provider": "google_workspace", "error": error}

    try:
        data = json.loads(result.stdout)
    except Exception:
        return {
            "success": False,
            "provider": "google_workspace",
            "error": "Google Workspace calendar helper returned non-JSON output.",
        }

    return {
        "success": True,
        "provider": "google_workspace",
        "external_event_id": str(data.get("id") or ""),
        "html_link": str(data.get("htmlLink") or data.get("html_link") or ""),
        "raw_result": data if isinstance(data, Mapping) else {},
    }


def _create_external_calendar_event(
    payload: Mapping[str, Any],
    *,
    subject_owner_id: str,
) -> dict[str, Any] | None:
    provider_config = _calendar_external_config(subject_owner_id)
    if not provider_config:
        return None
    if provider_config.get("error"):
        return {
            "success": False,
            "provider": str(provider_config.get("provider") or "unknown"),
            "error": str(provider_config.get("error")),
        }
    return _create_google_workspace_calendar_event(payload, provider_config)


def list_calendar_entries(
    *,
    subject_owner_id: str | None = None,
    statuses: set[str] | None = None,
) -> list[dict[str, Any]]:
    owner_id = str(subject_owner_id or "").strip()
    allowed_statuses = {str(status) for status in statuses} if statuses else None
    entries: list[dict[str, Any]] = []
    for event in _read_calendar_events().get("events", []):
        if not isinstance(event, dict):
            continue
        if owner_id and event.get("subject_owner_id") != owner_id:
            continue
        if allowed_statuses and str(event.get("status") or "") not in allowed_statuses:
            continue
        entries.append(dict(event))
    entries.sort(key=lambda item: str(item.get("start") or ""))
    return entries


def _is_expired(request: Mapping[str, Any], now: datetime) -> bool:
    expires_at = _parse_datetime(request.get("expires_at"))
    return bool(expires_at and expires_at <= now)


def expire_stale_requests(now: datetime | None = None) -> int:
    """Mark expired pending requests and return the number updated."""

    now = now or _utcnow()
    with _approval_store_lock():
        data = read_approval_store()
        changed = 0
        for request in data.get("requests", []):
            if not isinstance(request, dict):
                continue
            if request.get("status") == "pending" and _is_expired(request, now):
                request["status"] = "expired"
                request["expired_at"] = now.isoformat()
                _audit_request_event("approval_expired", request)
                changed += 1
        if changed:
            write_approval_store(data)
    return changed


def create_approval_request(
    *,
    action_type: str,
    payload: Mapping[str, Any],
    risk: str,
    summary: str,
    requester: str = "unknown",
    subject_owner_id: str = "unresolved",
    requester_context: Mapping[str, Any] | None = None,
    expires_in: timedelta = timedelta(days=7),
) -> dict[str, Any]:
    now = _utcnow()
    request = {
        "id": f"{APPROVAL_ID_PREFIX}{uuid.uuid4().hex[:12]}",
        "status": "pending",
        "requester": requester or "unknown",
        "subject_owner_id": subject_owner_id or "unresolved",
        "action_type": action_type,
        "summary": summary,
        "proposed_payload": dict(payload),
        "risk": risk,
        "created_at": now.isoformat(),
        "expires_at": (now + expires_in).isoformat(),
    }
    if requester_context:
        request["requester_context"] = dict(requester_context)

    with _approval_store_lock():
        data = read_approval_store()
        data.setdefault("requests", []).append(request)
        write_approval_store(data)
    _audit_request_event("approval_requested", request)
    _notify_approval_request(request)
    return request


def create_memory_migration_request(
    *,
    subject_owner_id: str,
    requester: str = "owner",
    requester_context: Mapping[str, Any] | None = None,
    expires_in: timedelta = timedelta(days=7),
) -> dict[str, Any]:
    """Create an owner-confirmed request to migrate legacy global USER.md.

    The migration is deliberately request/approval based so old global user
    profile memory only moves into an owner-private namespace after explicit
    owner confirmation.
    """

    owner_id = str(subject_owner_id or "").strip()
    if not owner_id:
        return {
            "success": False,
            "error": "missing_owner",
            "message": "A subject owner id is required for memory migration.",
        }

    from tools.memory_tool import MemoryStore, get_memory_dir

    legacy_path = get_memory_dir() / "USER.md"
    legacy_entries = MemoryStore._read_file(legacy_path)
    if not legacy_entries:
        return {
            "success": False,
            "error": "no_legacy_user_memory",
            "message": "No legacy global USER.md entries were found to migrate.",
        }

    request = create_approval_request(
        action_type="memory_migration",
        payload={
            "source": "legacy_global_user_memory",
            "destination": "owner_private_memory",
            "entry_count": len(legacy_entries),
        },
        risk="medium",
        summary=f"Migrate {len(legacy_entries)} legacy USER.md entr{'y' if len(legacy_entries) == 1 else 'ies'} into owner memory",
        requester=requester,
        subject_owner_id=owner_id,
        requester_context=requester_context,
        expires_in=expires_in,
    )
    return {
        "success": True,
        "request": request,
        "message": f"Created memory migration approval `{request['id']}`.",
    }


def list_pending_requests(subject_owner_id: str | None = None) -> list[dict[str, Any]]:
    expire_stale_requests()
    owner = str(subject_owner_id or "").strip()
    pending: list[dict[str, Any]] = []
    for request in read_approval_store().get("requests", []):
        if not isinstance(request, dict):
            continue
        if request.get("status") != "pending":
            continue
        if owner and request.get("subject_owner_id") != owner:
            continue
        pending.append(dict(request))
    pending.sort(key=lambda item: str(item.get("created_at") or ""))
    return pending


def _find_request(data: Mapping[str, Any], request_id: str) -> dict[str, Any] | None:
    for request in data.get("requests", []):
        if isinstance(request, dict) and request.get("id") == request_id:
            return request
    return None


def _owner_can_resolve(request: Mapping[str, Any], owner_ids: set[str] | None) -> bool:
    if not owner_ids:
        return True
    return str(request.get("subject_owner_id") or "") in owner_ids


def _record_calendar_payload(
    payload: Mapping[str, Any],
    *,
    subject_owner_id: str,
    requester: str,
    status: str,
    id_prefix: str,
    audit_event_type: str,
    result_message: str,
    approval_request_id: str = "",
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or _utcnow()
    approval_id = str(approval_request_id or "").strip()
    event_id_seed = approval_id.removeprefix(APPROVAL_ID_PREFIX) if approval_id else uuid.uuid4().hex[:12]
    event_id = f"{id_prefix}_{event_id_seed}"
    data = _read_calendar_events()
    if approval_id:
        for event in data.get("events", []):
            if isinstance(event, dict) and event.get("approval_request_id") == approval_id:
                return {
                    "status": "already_committed",
                    "event_id": event.get("id") or event_id,
                    "message": "Calendar request was already recorded in the local calendar ledger.",
                }

    event = {
        "id": event_id,
        "status": status,
        "approval_request_id": approval_id,
        "subject_owner_id": subject_owner_id,
        "requester": requester,
        "summary": str(payload.get("summary") or ""),
        "start": str(payload.get("start") or ""),
        "end": str(payload.get("end") or ""),
        "timezone": str(payload.get("timezone") or ""),
        "attendees": payload.get("attendees") if isinstance(payload.get("attendees"), list) else [],
        "location": str(payload.get("location") or ""),
        "description": str(payload.get("description") or ""),
        "committed_at": now.isoformat(),
        "external_effect": "none",
    }
    external_result = None
    if status == "committed_local":
        external_result = _create_external_calendar_event(
            payload,
            subject_owner_id=subject_owner_id,
        )
    if isinstance(external_result, Mapping):
        provider = str(external_result.get("provider") or "unknown")
        event["external_provider"] = provider
        if external_result.get("success"):
            event["status"] = "committed_external"
            event["external_effect"] = "calendar_create"
            event["external_event_id"] = str(external_result.get("external_event_id") or "")
            event["external_link"] = str(external_result.get("html_link") or "")
        else:
            event["status"] = "external_failed"
            event["external_effect"] = "none"
            event["external_error"] = str(external_result.get("error") or "external calendar provider failed")
    data.setdefault("events", []).append(event)
    _write_calendar_events(data)
    try:
        from gateway.owner_audit import append_audit_event

        append_audit_event(
            subject_owner_id=subject_owner_id,
            event_type=audit_event_type,
            requester=requester,
            details={
                "event_id": event_id,
                "approval_request_id": approval_id,
                "summary": event["summary"],
                "status": event["status"],
                "external_effect": event["external_effect"],
                "external_provider": event.get("external_provider", ""),
                "external_event_id": event.get("external_event_id", ""),
            },
        )
    except Exception:
        pass
    if event["status"] == "committed_external":
        return {
            "status": "committed_external",
            "event_id": event_id,
            "external_effect": "calendar_create",
            "external_provider": event.get("external_provider", ""),
            "external_event_id": event.get("external_event_id", ""),
            "external_link": event.get("external_link", ""),
            "message": "Approved calendar request created in the external calendar provider and recorded locally.",
        }
    if event["status"] == "external_failed":
        return {
            "status": "external_failed",
            "event_id": event_id,
            "external_effect": "none",
            "external_provider": event.get("external_provider", ""),
            "error": event.get("external_error", ""),
            "message": (
                "External calendar provider failed; no external event was created. "
                "The request was recorded in the local ledger for owner review."
            ),
        }
    return {
        "status": status,
        "event_id": event_id,
        "external_effect": "none",
        "message": result_message,
    }


def commit_calendar_payload(
    payload: Mapping[str, Any],
    *,
    subject_owner_id: str,
    requester: str,
    approval_request_id: str = "",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Record a policy-approved calendar event and optionally create it externally."""

    return _record_calendar_payload(
        payload,
        subject_owner_id=subject_owner_id,
        requester=requester,
        approval_request_id=approval_request_id,
        now=now,
        status="committed_local",
        id_prefix="cal",
        audit_event_type="calendar_committed",
        result_message=(
            "Approved calendar request recorded in the local calendar ledger. "
            "No external calendar provider was called."
        ),
    )


def hold_calendar_payload(
    payload: Mapping[str, Any],
    *,
    subject_owner_id: str,
    requester: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Record a policy-approved tentative calendar hold in the local ledger."""

    return _record_calendar_payload(
        payload,
        subject_owner_id=subject_owner_id,
        requester=requester,
        now=now,
        status="held_local",
        id_prefix="hold",
        audit_event_type="calendar_held",
        result_message=(
            "Tentative calendar hold recorded in the local calendar ledger. "
            "No external calendar provider was called."
        ),
    )


def _commit_calendar_request(request: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    payload = request.get("proposed_payload")
    payload = payload if isinstance(payload, Mapping) else {}
    return commit_calendar_payload(
        payload,
        subject_owner_id=str(request.get("subject_owner_id") or "unresolved"),
        requester=str(request.get("requester") or ""),
        approval_request_id=str(request.get("id") or ""),
        now=now,
    )


def _execute_memory_migration(request: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    from tools.memory_tool import ENTRY_DELIMITER, MemoryStore, get_memory_dir

    owner_id = str(request.get("subject_owner_id") or "").strip()
    if not owner_id:
        return {
            "status": "failed",
            "error": "missing_owner",
            "message": "Memory migration could not run because the owner id is missing.",
        }

    legacy_path = get_memory_dir() / "USER.md"
    legacy_entries = MemoryStore._read_file(legacy_path)
    if not legacy_entries:
        return {
            "status": "no_legacy_user_memory",
            "copied_count": 0,
            "skipped_count": 0,
            "message": "No legacy global USER.md entries were found to migrate.",
        }

    store = MemoryStore(owner_namespace=owner_id, use_owner_memory=True)
    target_path = store._path_for("memory")
    with store._file_lock(target_path):
        drift_backup = store._reload_target("memory")
        if drift_backup:
            return {
                "status": "failed",
                "error": "destination_drift",
                "drift_backup": drift_backup,
                "message": (
                    "Owner memory had external edits that need review before migration. "
                    "No entries were copied."
                ),
            }

        existing = list(store.memory_entries)
        unique_to_copy = []
        skipped_count = 0
        for entry in legacy_entries:
            normalized = str(entry or "").strip()
            if not normalized or normalized in existing or normalized in unique_to_copy:
                skipped_count += 1
                continue
            unique_to_copy.append(normalized)

        if not unique_to_copy:
            return {
                "status": "already_migrated",
                "copied_count": 0,
                "skipped_count": skipped_count,
                "destination": "owner_private_memory",
                "message": "Legacy USER.md entries were already present in owner memory.",
            }

        proposed = existing + unique_to_copy
        proposed_size = len(ENTRY_DELIMITER.join(proposed))
        if proposed_size > store.memory_char_limit:
            return {
                "status": "failed",
                "error": "memory_limit_exceeded",
                "copied_count": 0,
                "skipped_count": skipped_count,
                "current_entries": len(existing),
                "pending_entries": len(unique_to_copy),
                "message": (
                    "Legacy USER.md entries would exceed the owner memory limit. "
                    "No entries were copied; curate the legacy file first."
                ),
            }

        store.memory_entries = proposed
        store.save_to_disk("memory")

    try:
        from gateway.owner_audit import append_audit_event

        append_audit_event(
            subject_owner_id=owner_id,
            event_type="memory_migrated",
            requester=str(request.get("requester") or ""),
            details={
                "approval_request_id": request.get("id"),
                "source": "legacy_global_user_memory",
                "destination": "owner_private_memory",
                "copied_count": len(unique_to_copy),
                "skipped_count": skipped_count,
                "external_effect": "none",
            },
        )
    except Exception:
        pass

    return {
        "status": "migrated",
        "copied_count": len(unique_to_copy),
        "skipped_count": skipped_count,
        "destination": "owner_private_memory",
        "external_effect": "none",
        "message": (
            f"Migrated {len(unique_to_copy)} legacy USER.md entr"
            f"{'y' if len(unique_to_copy) == 1 else 'ies'} into owner-private memory. "
            "The legacy USER.md file was left unchanged."
        ),
    }


def _execute_send_message_request(request: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    payload = request.get("proposed_payload")
    payload = payload if isinstance(payload, Mapping) else {}
    target = str(payload.get("target") or "").strip()
    message = str(payload.get("message") or "").strip()
    if not target or not message:
        return {
            "status": "failed",
            "error": "missing_message_payload",
            "external_effect": "none",
            "message": "Approved message request was missing a target or message.",
        }

    try:
        from tools.send_message_tool import send_message_tool

        raw_result = send_message_tool(
            {
                "action": "send",
                "target": target,
                "message": message,
            },
            owner_approved=True,
        )
        send_result = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
        if not isinstance(send_result, Mapping):
            send_result = {"error": f"Unexpected send result type: {type(send_result).__name__}"}
    except Exception as exc:
        send_result = {"error": str(exc)}

    success = bool(send_result.get("success")) if isinstance(send_result, Mapping) else False
    if success:
        try:
            from gateway.owner_audit import append_audit_event

            append_audit_event(
                subject_owner_id=str(request.get("subject_owner_id") or "unresolved"),
                event_type="message_sent",
                requester=str(request.get("requester") or ""),
                details={
                    "approval_request_id": request.get("id"),
                    "target": target,
                    "external_effect": "message_send",
                    "message_id": send_result.get("message_id") if isinstance(send_result, Mapping) else "",
                },
            )
        except Exception:
            pass
        return {
            "status": "sent",
            "target": target,
            "external_effect": "message_send",
            "send_result": dict(send_result),
            "message": f"Approved message request sent to `{target}`.",
        }

    return {
        "status": "failed",
        "target": target,
        "external_effect": "none",
        "send_result": dict(send_result) if isinstance(send_result, Mapping) else {},
        "message": f"Owner approved the message request, but sending to `{target}` failed.",
    }


def _execute_request(request: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    action_type = str(request.get("action_type") or "")
    if action_type == "calendar_request":
        return _commit_calendar_request(request, now)
    if action_type == "memory_migration":
        return _execute_memory_migration(request, now)
    if action_type == "send_message":
        return _execute_send_message_request(request, now)
    return {
        "status": "recorded",
        "message": f"Approval recorded for unsupported action type '{action_type}'.",
    }


def approve_request(
    request_id: str,
    *,
    owner_principal: str = "",
    owner_ids: set[str] | None = None,
    allowed_action_types: set[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or _utcnow()
    request_id = str(request_id or "").strip()
    allowed_actions = (
        {str(action) for action in allowed_action_types}
        if allowed_action_types is not None else None
    )
    with _approval_store_lock():
        data = read_approval_store()
        request = _find_request(data, request_id)
        if request is None:
            return {"success": False, "error": "not_found", "message": f"No owner approval request `{request_id}` was found."}
        if not _owner_can_resolve(request, owner_ids):
            return {"success": False, "error": "forbidden", "message": "That approval belongs to a different owner."}
        action_type = str(request.get("action_type") or "")
        if allowed_actions is not None and action_type not in allowed_actions:
            return {
                "success": False,
                "error": "wrong_action_type",
                "action_type": action_type,
                "message": f"Approval `{request_id}` is not a supported request type for this tool.",
            }
        if request.get("status") != "pending":
            return {
                "success": False,
                "error": "not_pending",
                "status": request.get("status"),
                "message": f"Approval `{request_id}` is already {request.get('status')}.",
            }
        if _is_expired(request, now):
            request["status"] = "expired"
            request["expired_at"] = now.isoformat()
            write_approval_store(data)
            _audit_request_event("approval_expired", request)
            return {"success": False, "error": "expired", "message": f"Approval `{request_id}` has expired."}

        execution = _execute_request(request, now)
        request["status"] = "approved"
        request["approved_at"] = now.isoformat()
        request["approved_by"] = owner_principal or "owner"
        request["execution_result"] = execution
        write_approval_store(data)
        _audit_request_event(
            "approval_approved",
            request,
            {"approved_by": request["approved_by"], "execution_result": execution},
        )
        return {
            "success": True,
            "request": dict(request),
            "execution_result": execution,
            "message": execution.get("message") or f"Approved `{request_id}`.",
        }


def deny_request(
    request_id: str,
    *,
    owner_principal: str = "",
    owner_ids: set[str] | None = None,
    reason: str = "",
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or _utcnow()
    request_id = str(request_id or "").strip()
    with _approval_store_lock():
        data = read_approval_store()
        request = _find_request(data, request_id)
        if request is None:
            return {"success": False, "error": "not_found", "message": f"No owner approval request `{request_id}` was found."}
        if not _owner_can_resolve(request, owner_ids):
            return {"success": False, "error": "forbidden", "message": "That approval belongs to a different owner."}
        if request.get("status") != "pending":
            return {
                "success": False,
                "error": "not_pending",
                "status": request.get("status"),
                "message": f"Approval `{request_id}` is already {request.get('status')}.",
            }
        if _is_expired(request, now):
            request["status"] = "expired"
            request["expired_at"] = now.isoformat()
            write_approval_store(data)
            _audit_request_event("approval_expired", request)
            return {"success": False, "error": "expired", "message": f"Approval `{request_id}` has expired."}

        request["status"] = "denied"
        request["denied_at"] = now.isoformat()
        request["denied_by"] = owner_principal or "owner"
        request["denial_reason"] = reason
        request["safe_response"] = (
            "The owner declined this request."
            if not reason
            else f"The owner declined this request: {reason}"
        )
        write_approval_store(data)
        _audit_request_event(
            "approval_denied",
            request,
            {"denied_by": request["denied_by"], "reason": reason},
        )
        return {
            "success": True,
            "request": dict(request),
            "message": f"Denied `{request_id}`.",
        }


__all__ = [
    "APPROVAL_ID_PREFIX",
    "approval_store_path",
    "approve_request",
    "calendar_events_path",
    "commit_calendar_payload",
    "create_approval_request",
    "create_memory_migration_request",
    "deny_request",
    "expire_stale_requests",
    "hold_calendar_payload",
    "list_calendar_entries",
    "list_pending_requests",
    "read_approval_store",
    "reset_current_approval_notifier",
    "set_current_approval_notifier",
    "write_approval_store",
]
