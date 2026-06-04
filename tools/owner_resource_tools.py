"""Owner-scoped resource wrapper tools.

These tools are intentionally narrow. They let correspondents ask for
owner-mediated actions without directly reading or mutating owner-private
calendar data.
"""

from __future__ import annotations

import json
import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from agent.redact import redact_sensitive_text
from gateway.owner_approvals import (
    approve_request,
    commit_calendar_payload,
    create_approval_request,
    hold_calendar_payload,
    list_calendar_entries,
)
from tools.binary_extensions import has_binary_extension
from tools.registry import registry


_OWNER_FILE_DEFAULT_LINE_LIMIT = 200
_OWNER_FILE_MAX_LINE_LIMIT = 500
_OWNER_FILE_DEFAULT_SEARCH_LIMIT = 20
_OWNER_FILE_MAX_SEARCH_LIMIT = 100
_OWNER_FILE_SEARCH_MAX_BYTES = 512_000


OWNER_AVAILABILITY_SCHEMA = {
    "name": "owner_availability",
    "description": (
        "Return policy-safe owner availability information. Results are "
        "free/busy-style windows only and never include event titles, "
        "attendees, locations, descriptions, or private notes."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "start": {
                "type": "string",
                "description": "Start of the requested range, ideally ISO 8601.",
            },
            "end": {
                "type": "string",
                "description": "End of the requested range, ideally ISO 8601.",
            },
            "timezone": {
                "type": "string",
                "description": "Requester or owner timezone if known.",
            },
            "duration_minutes": {
                "type": "integer",
                "description": "Desired meeting length in minutes.",
            },
        },
    },
}


CALENDAR_REQUEST_SCHEMA = {
    "name": "calendar_request",
    "description": (
        "Create a pending owner approval request for a calendar action. This "
        "does not create, update, or delete calendar events."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Brief requested meeting title or purpose.",
            },
            "start": {
                "type": "string",
                "description": "Requested start time, ideally ISO 8601 with timezone.",
            },
            "end": {
                "type": "string",
                "description": "Requested end time, ideally ISO 8601 with timezone.",
            },
            "timezone": {
                "type": "string",
                "description": "Timezone for start/end if not explicit.",
            },
            "attendees": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Requested attendee email addresses or names.",
            },
            "location": {
                "type": "string",
                "description": "Requested location or meeting link preference.",
            },
            "description": {
                "type": "string",
                "description": "Short note to show the owner.",
            },
        },
        "required": ["summary", "start", "end"],
    },
}


CALENDAR_COMMIT_SCHEMA = {
    "name": "calendar_commit",
    "description": (
        "Commit a calendar event only when the requester is the owner or has "
        "an explicit calendar write delegation. This records a local calendar "
        "ledger entry and, when owner config explicitly opts in, creates the "
        "event through an external calendar provider."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "approval_request_id": {
                "type": "string",
                "description": "Optional pending owner approval id to approve and commit.",
            },
            "summary": {
                "type": "string",
                "description": "Meeting title or purpose for direct owner/delegated commits.",
            },
            "start": {
                "type": "string",
                "description": "Start time, ideally ISO 8601 with timezone.",
            },
            "end": {
                "type": "string",
                "description": "End time, ideally ISO 8601 with timezone.",
            },
            "timezone": {
                "type": "string",
                "description": "Timezone for start/end if not explicit.",
            },
            "attendees": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Attendee email addresses or names.",
            },
            "location": {
                "type": "string",
                "description": "Location or meeting link.",
            },
            "description": {
                "type": "string",
                "description": "Short event description.",
            },
        },
    },
}


CALENDAR_HOLD_SCHEMA = {
    "name": "calendar_hold",
    "description": (
        "Record a tentative local calendar hold only when the requester is the "
        "owner or has explicit calendar hold/write delegation. This does not "
        "create an external calendar event."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Meeting title or purpose for the tentative hold.",
            },
            "start": {
                "type": "string",
                "description": "Start time, ideally ISO 8601 with timezone.",
            },
            "end": {
                "type": "string",
                "description": "End time, ideally ISO 8601 with timezone.",
            },
            "timezone": {
                "type": "string",
                "description": "Timezone for start/end if not explicit.",
            },
            "attendees": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Attendee email addresses or names.",
            },
            "location": {
                "type": "string",
                "description": "Location or meeting link.",
            },
            "description": {
                "type": "string",
                "description": "Short hold description.",
            },
        },
        "required": ["summary", "start", "end"],
    },
}


OWNER_FILE_READ_SCHEMA = {
    "name": "owner_file_read",
    "description": (
        "Read a text file only from a policy-delegated owner file root. "
        "The path must be relative to the named root and the returned content "
        "is redacted before it enters model context."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "root": {
                "type": "string",
                "description": "Delegated root name. Optional when exactly one root is configured.",
            },
            "path": {
                "type": "string",
                "description": "Relative path inside the delegated root.",
            },
            "offset": {
                "type": "integer",
                "description": "1-indexed line number to start reading from.",
                "default": 1,
                "minimum": 1,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of lines to return.",
                "default": _OWNER_FILE_DEFAULT_LINE_LIMIT,
                "maximum": _OWNER_FILE_MAX_LINE_LIMIT,
            },
        },
        "required": ["path"],
    },
}


OWNER_FILE_SEARCH_SCHEMA = {
    "name": "owner_file_search",
    "description": (
        "Search text files inside a policy-delegated owner file root. "
        "Results only include relative paths and redacted matching lines."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "root": {
                "type": "string",
                "description": "Delegated root name. Optional when exactly one root is configured.",
            },
            "query": {
                "type": "string",
                "description": "Literal text to search for.",
            },
            "file_glob": {
                "type": "string",
                "description": "Optional file glob such as '*.md' or '*.txt'.",
                "default": "*",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of matches to return.",
                "default": _OWNER_FILE_DEFAULT_SEARCH_LIMIT,
                "maximum": _OWNER_FILE_MAX_SEARCH_LIMIT,
            },
        },
        "required": ["query"],
    },
}


def _policy_context():
    try:
        from gateway.permissions import get_current_permission_context

        return get_current_permission_context()
    except Exception:
        return None


def _load_config() -> Mapping[str, Any]:
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
        return cfg if isinstance(cfg, Mapping) else {}
    except Exception:
        return {}


def _owner_id_from_context_or_args(args: Mapping[str, Any]) -> str:
    ctx = _policy_context()
    owner_id = getattr(ctx, "subject_owner_id", "") if ctx is not None else ""
    return str(owner_id or args.get("owner_id") or "").strip()


def _calendar_write_allowed() -> bool:
    return _calendar_resource_allowed("write")


def _calendar_resource_allowed(action: str) -> bool:
    ctx = _policy_context()
    if ctx is None:
        return False
    if bool(getattr(ctx, "is_owner", False)):
        return True
    rules = getattr(ctx, "resource_rules", {}) or {}
    calendar = rules.get("calendar") if isinstance(rules, Mapping) else {}
    if not isinstance(calendar, Mapping):
        return False
    action = str(action or "").strip().lower()
    if action == "hold":
        return str(calendar.get("hold") or "").strip().lower() == "allow" or str(
            calendar.get("write") or ""
        ).strip().lower() == "allow"
    return str(calendar.get(action) or "").strip().lower() == "allow"


def _file_resource_rules() -> Mapping[str, Any]:
    ctx = _policy_context()
    rules = getattr(ctx, "resource_rules", {}) if ctx is not None else {}
    files = rules.get("files") if isinstance(rules, Mapping) else {}
    if isinstance(files, Mapping):
        return files
    if isinstance(files, str):
        return {"read": files}
    return {}


def _file_read_allowed() -> bool:
    ctx = _policy_context()
    if ctx is None:
        return False
    if bool(getattr(ctx, "is_owner", False)):
        return True
    decision = _file_resource_rules().get("read")
    if isinstance(decision, bool):
        return decision
    return str(decision or "").strip().lower() in {"allow", "allowed", "read", "redact"}


def _redaction_enabled(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", "raw", "none"}


def _file_root_entries(files: Mapping[str, Any]) -> list[dict[str, Any]]:
    default_redact = files.get("redact", True)
    raw_roots = files.get("roots") or files.get("read_roots") or files.get("allowed_roots")
    if raw_roots is None:
        for key in ("path", "root", "dir"):
            if files.get(key):
                raw_roots = [{
                    "name": files.get("name") or "default",
                    "path": files.get(key),
                    "redact": default_redact,
                }]
                break

    entries: list[dict[str, Any]] = []

    def add_entry(name: Any, value: Any, index: int) -> None:
        if isinstance(value, Mapping):
            path = value.get("path") or value.get("root") or value.get("dir")
            root_name = value.get("name") or name
            redact = value.get("redact", default_redact)
        else:
            path = value
            root_name = name
            redact = default_redact
        path_text = str(path or "").strip()
        if not path_text:
            return
        name_text = str(root_name or "").strip()
        if not name_text:
            name_text = Path(path_text).name or f"root{index}"
        entries.append({
            "name": name_text,
            "path": path_text,
            "redact": _redaction_enabled(redact),
        })

    if isinstance(raw_roots, Mapping):
        for index, (name, value) in enumerate(raw_roots.items(), start=1):
            add_entry(name, value, index)
    elif isinstance(raw_roots, list | tuple):
        for index, value in enumerate(raw_roots, start=1):
            add_entry("", value, index)
    elif raw_roots is not None:
        add_entry(files.get("name") or "default", raw_roots, 1)
    return entries


def _owner_file_error(message: str, **extra: Any) -> str:
    return json.dumps({"success": False, "error": message, **extra}, ensure_ascii=False)


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _select_owner_file_root(args: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    if not _file_read_allowed():
        return None, "Owner file access requires explicit file read delegation."
    roots = _file_root_entries(_file_resource_rules())
    if not roots:
        return None, "No owner file roots are delegated for this requester."

    requested = str(args.get("root") or "").strip()
    if requested:
        for root in roots:
            if root["name"] == requested:
                return root, None
        available = [root["name"] for root in roots]
        return None, f"Unknown delegated file root '{requested}'. Available roots: {available}."
    if len(roots) == 1:
        return roots[0], None
    available = [root["name"] for root in roots]
    return None, f"Multiple delegated file roots are available; specify one of {available}."


def _resolve_owner_file_path(root: Mapping[str, Any], logical_path: Any) -> tuple[Path | None, str, str | None]:
    raw_path = str(logical_path or "").strip()
    if not raw_path:
        return None, "", "path is required."
    requested_path = Path(raw_path)
    if requested_path.is_absolute() or raw_path.startswith("~"):
        return None, "", "path must be relative to the delegated root."
    if ".." in requested_path.parts:
        return None, "", "path must stay within the delegated root."

    try:
        root_path = Path(str(root["path"])).expanduser().resolve(strict=True)
    except OSError as exc:
        return None, "", f"Delegated file root is unavailable: {exc}."
    if not root_path.is_dir():
        return None, "", "Delegated file root is not a directory."

    resolved = (root_path / requested_path).resolve(strict=False)
    if not _is_relative_to(resolved, root_path):
        return None, "", "path must stay within the delegated root."
    try:
        relative = resolved.relative_to(root_path).as_posix()
    except ValueError:
        return None, "", "path must stay within the delegated root."
    return resolved, relative, None


def _should_redact_file_content(root: Mapping[str, Any]) -> bool:
    ctx = _policy_context()
    return bool(root.get("redact", True)) or not bool(getattr(ctx, "is_owner", False))


def _redact_owner_file_content(text: str, root: Mapping[str, Any]) -> str:
    if not _should_redact_file_content(root):
        return text
    return redact_sensitive_text(text, force=True)


def _owner_block(owner_id: str) -> Mapping[str, Any]:
    owners = _load_config().get("owners")
    if not isinstance(owners, Mapping):
        return {}
    block = owners.get(owner_id)
    return block if isinstance(block, Mapping) else {}


def _availability_entries(owner_id: str) -> list[Mapping[str, Any]]:
    availability = _owner_block(owner_id).get("availability")
    if not isinstance(availability, Mapping):
        return []
    for key in ("busy", "freebusy", "windows"):
        value = availability.get(key)
        if isinstance(value, list):
            return [entry for entry in value if isinstance(entry, Mapping)]
    return []


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


def _entry_overlaps_range(entry: Mapping[str, Any], args: Mapping[str, Any]) -> bool:
    range_start = _parse_datetime(args.get("start"))
    range_end = _parse_datetime(args.get("end"))
    if range_start is None and range_end is None:
        return True
    entry_start = _parse_datetime(entry.get("start"))
    entry_end = _parse_datetime(entry.get("end"))
    if entry_start is None or entry_end is None:
        return True
    if range_start is not None and entry_end <= range_start:
        return False
    if range_end is not None and entry_start >= range_end:
        return False
    return True


def _local_calendar_availability_entries(owner_id: str) -> list[Mapping[str, Any]]:
    entries: list[Mapping[str, Any]] = []
    for event in list_calendar_entries(
        subject_owner_id=owner_id,
        statuses={"committed_local", "committed_external", "held_local"},
    ):
        entries.append({
            "start": event.get("start") or "",
            "end": event.get("end") or "",
            "status": "tentative" if event.get("status") == "held_local" else "busy",
        })
    return entries


def _redacted_availability_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: str(entry[key])
        for key in ("start", "end", "status")
        if entry.get(key) is not None
    }


def owner_availability_tool(args: dict, **kwargs) -> str:
    owner_id = _owner_id_from_context_or_args(args)
    if not owner_id:
        return json.dumps({
            "success": False,
            "error": "No subject owner is available for this request.",
        }, ensure_ascii=False)

    entries = [*_availability_entries(owner_id), *_local_calendar_availability_entries(owner_id)]
    windows = [
        _redacted_availability_entry(entry)
        for entry in entries
        if _entry_overlaps_range(entry, args)
    ]
    return json.dumps({
        "success": True,
        "owner": owner_id,
        "range": {
            "start": args.get("start") or "",
            "end": args.get("end") or "",
            "timezone": args.get("timezone") or "",
            "duration_minutes": args.get("duration_minutes"),
        },
        "availability": windows,
        "disclosure": "freebusy_only",
        "message": (
            "No configured owner availability windows were found."
            if not windows
            else "Availability is redacted to start/end/status only."
        ),
    }, ensure_ascii=False)


def _create_owner_approval_request(
    *,
    action_type: str,
    payload: Mapping[str, Any],
    risk: str,
    summary: str,
) -> dict[str, Any]:
    ctx = _policy_context()
    requester = getattr(getattr(ctx, "requester", None), "key", "unknown")
    owner_id = getattr(ctx, "subject_owner_id", "") or str(payload.get("owner_id") or "unresolved")
    requester_context = {
        "platform": getattr(ctx, "platform", "") if ctx is not None else "",
        "relationship": getattr(ctx, "relationship", "") if ctx is not None else "",
        "policy_name": getattr(ctx, "policy_name", "") if ctx is not None else "",
        "session_key": getattr(ctx, "session_key", "") if ctx is not None else "",
    }
    return create_approval_request(
        action_type=action_type,
        payload=payload,
        risk=risk,
        summary=summary,
        requester=requester,
        subject_owner_id=owner_id,
        requester_context=requester_context,
    )


def calendar_request_tool(args: dict, **kwargs) -> str:
    summary = str(args.get("summary") or "").strip()
    start = str(args.get("start") or "").strip()
    end = str(args.get("end") or "").strip()
    if not summary or not start or not end:
        return json.dumps({
            "success": False,
            "error": "summary, start, and end are required.",
        }, ensure_ascii=False)

    owner_id = _owner_id_from_context_or_args(args)
    payload = {
        "owner_id": owner_id,
        "summary": summary,
        "start": start,
        "end": end,
        "timezone": args.get("timezone") or "",
        "attendees": args.get("attendees") if isinstance(args.get("attendees"), list) else [],
        "location": args.get("location") or "",
        "description": args.get("description") or "",
    }
    request = _create_owner_approval_request(
        action_type="calendar_request",
        payload=payload,
        risk="medium",
        summary=f"Calendar request: {summary}",
    )
    return json.dumps({
        "success": True,
        "approval_required": True,
        "approval_request_id": request["id"],
        "status": request["status"],
        "message": "Calendar request saved for owner approval. No calendar event was created.",
    }, ensure_ascii=False)


def calendar_commit_tool(args: dict, **kwargs) -> str:
    if not _calendar_write_allowed():
        return json.dumps({
            "success": False,
            "approval_required": True,
            "error": (
                "calendar_commit requires owner approval or explicit calendar "
                "write delegation. Use calendar_request instead."
            ),
        }, ensure_ascii=False)

    ctx = _policy_context()
    requester = getattr(getattr(ctx, "requester", None), "key", "unknown")
    owner_id = _owner_id_from_context_or_args(args) or getattr(ctx, "subject_owner_id", "")
    approval_request_id = str(args.get("approval_request_id") or "").strip()
    if approval_request_id:
        owner_ids = set(getattr(getattr(ctx, "requester", None), "owner_ids", set()) or set())
        if owner_id:
            owner_ids.add(owner_id)
        if not owner_ids:
            return json.dumps({
                "success": False,
                "error": "missing_owner_scope",
                "message": "calendar_commit approval requires a scoped owner.",
            }, ensure_ascii=False)
        result = approve_request(
            approval_request_id,
            owner_principal=requester,
            owner_ids=owner_ids,
            allowed_action_types={"calendar_request"},
        )
        return json.dumps(result, ensure_ascii=False)

    summary = str(args.get("summary") or "").strip()
    start = str(args.get("start") or "").strip()
    end = str(args.get("end") or "").strip()
    if not summary or not start or not end:
        return json.dumps({
            "success": False,
            "error": "summary, start, and end are required for direct calendar commits.",
        }, ensure_ascii=False)

    payload = {
        "owner_id": owner_id,
        "summary": summary,
        "start": start,
        "end": end,
        "timezone": args.get("timezone") or "",
        "attendees": args.get("attendees") if isinstance(args.get("attendees"), list) else [],
        "location": args.get("location") or "",
        "description": args.get("description") or "",
    }
    result = commit_calendar_payload(
        payload,
        subject_owner_id=owner_id or "unresolved",
        requester=requester,
    )
    failed = str(result.get("status") or "").startswith("external_failed")
    return json.dumps({
        "success": not failed,
        **result,
    }, ensure_ascii=False)


def calendar_hold_tool(args: dict, **kwargs) -> str:
    if not _calendar_resource_allowed("hold"):
        return json.dumps({
            "success": False,
            "approval_required": True,
            "error": (
                "calendar_hold requires owner approval or explicit calendar "
                "hold delegation. Use calendar_request instead."
            ),
        }, ensure_ascii=False)

    ctx = _policy_context()
    requester = getattr(getattr(ctx, "requester", None), "key", "unknown")
    owner_id = _owner_id_from_context_or_args(args) or getattr(ctx, "subject_owner_id", "")
    summary = str(args.get("summary") or "").strip()
    start = str(args.get("start") or "").strip()
    end = str(args.get("end") or "").strip()
    if not summary or not start or not end:
        return json.dumps({
            "success": False,
            "error": "summary, start, and end are required for calendar holds.",
        }, ensure_ascii=False)

    payload = {
        "owner_id": owner_id,
        "summary": summary,
        "start": start,
        "end": end,
        "timezone": args.get("timezone") or "",
        "attendees": args.get("attendees") if isinstance(args.get("attendees"), list) else [],
        "location": args.get("location") or "",
        "description": args.get("description") or "",
    }
    result = hold_calendar_payload(
        payload,
        subject_owner_id=owner_id or "unresolved",
        requester=requester,
    )
    return json.dumps({
        "success": True,
        **result,
    }, ensure_ascii=False)


def owner_file_read_tool(args: dict, **kwargs) -> str:
    root, error = _select_owner_file_root(args)
    if error:
        return _owner_file_error(error, approval_required=True)
    assert root is not None

    path, relative_path, error = _resolve_owner_file_path(root, args.get("path"))
    if error:
        return _owner_file_error(error)
    assert path is not None

    if has_binary_extension(str(path)):
        return _owner_file_error("Binary files cannot be read through owner_file_read.")
    if not path.exists() or not path.is_file():
        return _owner_file_error("File was not found inside the delegated root.")

    offset = _bounded_int(
        args.get("offset"),
        default=1,
        minimum=1,
        maximum=1_000_000,
    )
    limit = _bounded_int(
        args.get("limit"),
        default=_OWNER_FILE_DEFAULT_LINE_LIMIT,
        minimum=1,
        maximum=_OWNER_FILE_MAX_LINE_LIMIT,
    )

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _owner_file_error(f"Unable to read delegated file: {exc}.")

    text = _redact_owner_file_content(text, root)
    lines = text.splitlines()
    start = offset - 1
    selected = lines[start : start + limit]
    content = "\n".join(
        f"{line_number}|{line}"
        for line_number, line in enumerate(selected, start=offset)
    )
    return json.dumps({
        "success": True,
        "root": root["name"],
        "path": relative_path,
        "offset": offset,
        "line_count": len(selected),
        "total_lines": len(lines),
        "truncated": start + len(selected) < len(lines),
        "content": content,
        "disclosure": "scoped_file_read_redacted",
    }, ensure_ascii=False)


def owner_file_search_tool(args: dict, **kwargs) -> str:
    root, error = _select_owner_file_root(args)
    if error:
        return _owner_file_error(error, approval_required=True)
    assert root is not None

    query = str(args.get("query") or args.get("pattern") or "").strip()
    if not query:
        return _owner_file_error("query is required.")

    root_path, _, error = _resolve_owner_file_path(root, ".")
    if error:
        return _owner_file_error(error)
    assert root_path is not None

    file_glob = str(args.get("file_glob") or args.get("glob") or "*").strip() or "*"
    glob_path = Path(file_glob)
    if glob_path.is_absolute() or ".." in glob_path.parts:
        return _owner_file_error("file_glob must stay within the delegated root.")

    limit = _bounded_int(
        args.get("limit"),
        default=_OWNER_FILE_DEFAULT_SEARCH_LIMIT,
        minimum=1,
        maximum=_OWNER_FILE_MAX_SEARCH_LIMIT,
    )
    query_cmp = query.lower()
    matches: list[dict[str, Any]] = []
    truncated = False

    for candidate in sorted(root_path.rglob(file_glob), key=lambda p: p.as_posix()):
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            continue
        if not _is_relative_to(resolved, root_path) or not resolved.is_file():
            continue
        if has_binary_extension(str(resolved)):
            continue
        try:
            if resolved.stat().st_size > _OWNER_FILE_SEARCH_MAX_BYTES:
                continue
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            relative = resolved.relative_to(root_path).as_posix()
        except ValueError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if query_cmp not in line.lower():
                continue
            preview = line.strip()
            if len(preview) > 240:
                preview = preview[:237] + "..."
            preview = _redact_owner_file_content(preview, root)
            matches.append({
                "path": relative,
                "line": line_number,
                "preview": preview,
            })
            if len(matches) >= limit:
                truncated = True
                break
        if truncated:
            break

    return json.dumps({
        "success": True,
        "root": root["name"],
        "query": query,
        "matches": matches,
        "match_count": len(matches),
        "truncated": truncated,
        "disclosure": "scoped_file_search_redacted",
    }, ensure_ascii=False)


registry.register(
    name="owner_availability",
    toolset="owner_resources",
    schema=OWNER_AVAILABILITY_SCHEMA,
    handler=owner_availability_tool,
    emoji="",
)

registry.register(
    name="calendar_request",
    toolset="owner_resources",
    schema=CALENDAR_REQUEST_SCHEMA,
    handler=calendar_request_tool,
    emoji="",
)

registry.register(
    name="calendar_hold",
    toolset="owner_resources",
    schema=CALENDAR_HOLD_SCHEMA,
    handler=calendar_hold_tool,
    emoji="",
)

registry.register(
    name="calendar_commit",
    toolset="owner_resources",
    schema=CALENDAR_COMMIT_SCHEMA,
    handler=calendar_commit_tool,
    emoji="",
)

registry.register(
    name="owner_file_read",
    toolset="owner_resources",
    schema=OWNER_FILE_READ_SCHEMA,
    handler=owner_file_read_tool,
    emoji="",
    max_result_size_chars=100_000,
)

registry.register(
    name="owner_file_search",
    toolset="owner_resources",
    schema=OWNER_FILE_SEARCH_SCHEMA,
    handler=owner_file_search_tool,
    emoji="",
    max_result_size_chars=100_000,
)
