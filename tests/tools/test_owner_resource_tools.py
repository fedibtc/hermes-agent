import json
from types import SimpleNamespace

from gateway.permissions import (
    PermissionResolver,
    reset_current_permission_context,
    set_current_permission_context,
)
from gateway.owner_approvals import (
    create_approval_request,
    reset_current_approval_notifier,
    set_current_approval_notifier,
)
from tools.owner_resource_tools import (
    calendar_commit_tool,
    calendar_hold_tool,
    calendar_request_tool,
    owner_availability_tool,
    owner_file_read_tool,
    owner_file_search_tool,
)


def _source(user_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        platform="telegram",
        user_id=user_id,
        user_id_alt=None,
        user_name=user_id,
        chat_type="dm",
    )


def _config():
    return {
        "owners": {
            "owner": {
                "principals": ["telegram:owner"],
                "default_correspondent_policy": "coworker",
                "availability": {
                    "busy": [
                        {
                            "start": "2026-06-01T10:00:00Z",
                            "end": "2026-06-01T10:30:00Z",
                            "status": "busy",
                            "summary": "Private title",
                            "location": "Private room",
                            "description": "Private notes",
                        }
                    ]
                },
            }
        },
        "principals": {
            "telegram:employee": {
                "relationship": "coworker",
                "subject_owner": "owner",
            }
        },
        "policies": {
            "coworker": {
                "tools": {
                    "allow": ["owner_availability", "calendar_request"],
                }
            }
        },
    }


def _file_config(root):
    config = _config()
    config["principals"]["telegram:employee"]["relationship"] = "assistant"
    config["policies"]["assistant"] = {
        "tools": {"allow": ["owner_file_read", "owner_file_search"]},
        "resources": {
            "files": {
                "read": "allow",
                "redact": True,
                "roots": [{"name": "shared", "path": str(root)}],
            }
        },
    }
    return config


def test_owner_availability_returns_freebusy_only(monkeypatch):
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: config)

    try:
        result = json.loads(
            owner_availability_tool({
                "start": "2026-06-01T00:00:00Z",
                "end": "2026-06-02T00:00:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    assert result["owner"] == "owner"
    assert result["availability"] == [
        {
            "start": "2026-06-01T10:00:00Z",
            "end": "2026-06-01T10:30:00Z",
            "status": "busy",
        }
    ]
    assert "Private title" not in json.dumps(result)
    assert result["disclosure"] == "freebusy_only"


def test_owner_file_read_denies_without_file_delegation(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(owner_file_read_tool({"root": "shared", "path": "notes.txt"}))
    finally:
        reset_current_permission_context(token)

    assert result["success"] is False
    assert result["approval_required"] is True
    assert "file read delegation" in result["error"]


def test_owner_file_read_allows_configured_root_and_redacts(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()
    secret = "sk-1234567890abcdef"
    (root / "notes.txt").write_text(
        f"OPENAI_API_KEY={secret}\nhello from shared notes\n",
        encoding="utf-8",
    )
    config = _file_config(root)
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(owner_file_read_tool({"root": "shared", "path": "notes.txt"}))
    finally:
        reset_current_permission_context(token)

    serialized = json.dumps(result)
    assert result["success"] is True
    assert result["root"] == "shared"
    assert result["path"] == "notes.txt"
    assert "hello from shared notes" in result["content"]
    assert secret not in serialized
    assert str(root) not in serialized
    assert result["disclosure"] == "scoped_file_read_redacted"


def test_owner_file_read_blocks_traversal_and_symlink_escape(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret", encoding="utf-8")
    (root / "link.txt").symlink_to(outside)
    config = _file_config(root)
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        traversal = json.loads(owner_file_read_tool({"root": "shared", "path": "../outside.txt"}))
        symlink = json.loads(owner_file_read_tool({"root": "shared", "path": "link.txt"}))
    finally:
        reset_current_permission_context(token)

    assert traversal["success"] is False
    assert "within the delegated root" in traversal["error"]
    assert symlink["success"] is False
    assert "within the delegated root" in symlink["error"]


def test_owner_file_search_returns_relative_redacted_matches(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()
    secret = "sk-1234567890abcdef"
    (root / "brief.txt").write_text(
        f"AlphaProject uses token {secret}\n",
        encoding="utf-8",
    )
    nested = root / "nested"
    nested.mkdir()
    (nested / "brief.txt").write_text("AlphaProject next step\n", encoding="utf-8")
    config = _file_config(root)
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            owner_file_search_tool({
                "root": "shared",
                "query": "AlphaProject",
                "file_glob": "*.txt",
                "limit": 10,
            })
        )
    finally:
        reset_current_permission_context(token)

    serialized = json.dumps(result)
    assert result["success"] is True
    assert {match["path"] for match in result["matches"]} == {
        "brief.txt",
        "nested/brief.txt",
    }
    assert secret not in serialized
    assert str(root) not in serialized
    assert result["disclosure"] == "scoped_file_search_redacted"


def test_calendar_request_creates_pending_owner_approval(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            calendar_request_tool({
                "summary": "Planning",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
                "attendees": ["alice@example.com"],
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    assert result["approval_required"] is True
    assert result["status"] == "pending"

    store = json.loads((tmp_path / "owner_approvals" / "requests.json").read_text())
    request = store["requests"][0]
    assert request["id"] == result["approval_request_id"]
    assert request["requester"] == "telegram:employee"
    assert request["subject_owner_id"] == "owner"
    assert request["action_type"] == "calendar_request"
    assert request["proposed_payload"]["summary"] == "Planning"


def test_calendar_request_fires_owner_approval_notifier(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    policy_token = set_current_permission_context(ctx)
    notifications = []
    notifier_token = set_current_approval_notifier(lambda request: notifications.append(request))

    try:
        result = json.loads(
            calendar_request_tool({
                "summary": "Planning",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
            })
        )
    finally:
        reset_current_approval_notifier(notifier_token)
        reset_current_permission_context(policy_token)

    assert result["success"] is True
    assert len(notifications) == 1
    assert notifications[0]["id"] == result["approval_request_id"]
    assert notifications[0]["subject_owner_id"] == "owner"
    assert notifications[0]["requester"] == "telegram:employee"


def test_calendar_request_receives_policy_context_through_dispatch(monkeypatch, tmp_path):
    from model_tools import handle_function_call

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")

    result = json.loads(
        handle_function_call(
            "calendar_request",
            {
                "summary": "Dispatch path",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
            },
            enabled_tools=["calendar_request"],
            tool_policy_context=ctx,
        )
    )

    assert result["success"] is True
    store = json.loads((tmp_path / "owner_approvals" / "requests.json").read_text())
    request = store["requests"][0]
    assert request["requester"] == "telegram:employee"
    assert request["subject_owner_id"] == "owner"


def test_calendar_commit_denies_correspondent_without_write_delegation(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            calendar_commit_tool({
                "summary": "Direct write",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is False
    assert result["approval_required"] is True
    assert not (tmp_path / "owner_approvals" / "calendar_events.json").exists()


def test_calendar_commit_allows_owner_direct_local_commit(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("owner"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            calendar_commit_tool({
                "summary": "Owner planning",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
                "attendees": ["alice@example.com"],
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    assert result["status"] == "committed_local"
    assert result["external_effect"] == "none"
    events = json.loads((tmp_path / "owner_approvals" / "calendar_events.json").read_text())
    event = events["events"][0]
    assert event["summary"] == "Owner planning"
    assert event["requester"] == "telegram:owner"
    assert event["subject_owner_id"] == "owner"


def test_calendar_commit_allows_explicit_delegated_write(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    config["principals"]["telegram:employee"]["relationship"] = "assistant"
    config["policies"]["assistant"] = {
        "tools": {"allow": ["calendar_commit"]},
        "resources": {"calendar": {"write": "allow"}},
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            calendar_commit_tool({
                "summary": "Delegated planning",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    events = json.loads((tmp_path / "owner_approvals" / "calendar_events.json").read_text())
    assert events["events"][0]["requester"] == "telegram:employee"


def test_calendar_hold_denies_correspondent_without_hold_delegation(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            calendar_hold_tool({
                "summary": "Tentative planning",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is False
    assert result["approval_required"] is True
    assert not (tmp_path / "owner_approvals" / "calendar_events.json").exists()


def test_calendar_hold_allows_explicit_delegated_hold(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    config["principals"]["telegram:employee"]["relationship"] = "assistant"
    config["policies"]["assistant"] = {
        "tools": {"allow": ["calendar_hold"]},
        "resources": {"calendar": {"hold": "allow"}},
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)

    try:
        result = json.loads(
            calendar_hold_tool({
                "summary": "Tentative planning",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
                "attendees": ["alice@example.com"],
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    assert result["status"] == "held_local"
    assert result["external_effect"] == "none"
    events = json.loads((tmp_path / "owner_approvals" / "calendar_events.json").read_text())
    event = events["events"][0]
    assert event["id"].startswith("hold_")
    assert event["summary"] == "Tentative planning"
    assert event["requester"] == "telegram:employee"


def test_owner_availability_includes_local_commits_and_holds_freebusy_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: config)
    owner_ctx = PermissionResolver(config).resolve(_source("owner"), session_key="owner")
    token = set_current_permission_context(owner_ctx)
    try:
        json.loads(
            calendar_commit_tool({
                "summary": "Private committed title",
                "start": "2026-06-01T13:00:00Z",
                "end": "2026-06-01T13:30:00Z",
                "location": "Private room",
            })
        )
        json.loads(
            calendar_hold_tool({
                "summary": "Private hold title",
                "start": "2026-06-01T14:00:00Z",
                "end": "2026-06-01T14:30:00Z",
                "location": "Private link",
            })
        )
    finally:
        reset_current_permission_context(token)

    employee_ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(employee_ctx)
    try:
        result = json.loads(
            owner_availability_tool({
                "start": "2026-06-01T00:00:00Z",
                "end": "2026-06-02T00:00:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert {
        "start": "2026-06-01T13:00:00Z",
        "end": "2026-06-01T13:30:00Z",
        "status": "busy",
    } in result["availability"]
    assert {
        "start": "2026-06-01T14:00:00Z",
        "end": "2026-06-01T14:30:00Z",
        "status": "tentative",
    } in result["availability"]
    serialized = json.dumps(result)
    assert "Private committed title" not in serialized
    assert "Private hold title" not in serialized
    assert "Private room" not in serialized
    assert "Private link" not in serialized


def test_owner_availability_includes_external_commits_freebusy_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    config["owners"]["owner"]["calendar"] = {
        "external_commit": True,
        "provider": "google_workspace",
        "calendar_id": "primary",
    }
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: config)
    monkeypatch.setattr(
        "gateway.owner_approvals._create_google_workspace_calendar_event",
        lambda payload, provider_config: {
            "success": True,
            "provider": "google_workspace",
            "external_event_id": "gcal-123",
            "html_link": "https://calendar.example/gcal-123",
        },
    )

    owner_ctx = PermissionResolver(config).resolve(_source("owner"), session_key="owner")
    token = set_current_permission_context(owner_ctx)
    try:
        committed = json.loads(
            calendar_commit_tool({
                "summary": "Private external title",
                "start": "2026-06-01T15:00:00Z",
                "end": "2026-06-01T15:30:00Z",
                "location": "Private external room",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert committed["status"] == "committed_external"

    employee_ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(employee_ctx)
    try:
        result = json.loads(
            owner_availability_tool({
                "start": "2026-06-01T00:00:00Z",
                "end": "2026-06-02T00:00:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert {
        "start": "2026-06-01T15:00:00Z",
        "end": "2026-06-01T15:30:00Z",
        "status": "busy",
    } in result["availability"]
    serialized = json.dumps(result)
    assert "Private external title" not in serialized
    assert "Private external room" not in serialized


def test_calendar_commit_can_approve_pending_request_for_owner(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    employee_ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(employee_ctx)
    try:
        requested = json.loads(
            calendar_request_tool({
                "summary": "Approval path",
                "start": "2026-06-01T12:00:00Z",
                "end": "2026-06-01T12:30:00Z",
            })
        )
    finally:
        reset_current_permission_context(token)

    owner_ctx = PermissionResolver(config).resolve(_source("owner"), session_key="owner")
    token = set_current_permission_context(owner_ctx)
    try:
        result = json.loads(
            calendar_commit_tool({
                "approval_request_id": requested["approval_request_id"],
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    assert result["execution_result"]["status"] == "committed_local"
    store = json.loads((tmp_path / "owner_approvals" / "requests.json").read_text())
    assert store["requests"][0]["status"] == "approved"


def test_delegated_calendar_commit_cannot_approve_other_owner_request(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    config["principals"]["telegram:employee"]["relationship"] = "assistant"
    config["policies"]["assistant"] = {
        "tools": {"allow": ["calendar_commit"]},
        "resources": {"calendar": {"write": "allow"}},
    }
    request = create_approval_request(
        action_type="calendar_request",
        payload={
            "owner_id": "other-owner",
            "summary": "Other owner planning",
            "start": "2026-06-01T12:00:00Z",
            "end": "2026-06-01T12:30:00Z",
        },
        risk="medium",
        summary="Calendar request: Other owner planning",
        requester="telegram:other",
        subject_owner_id="other-owner",
    )
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)
    try:
        result = json.loads(
            calendar_commit_tool({
                "approval_request_id": request["id"],
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is False
    assert result["error"] == "forbidden"
    store = json.loads((tmp_path / "owner_approvals" / "requests.json").read_text())
    assert store["requests"][0]["status"] == "pending"


def test_calendar_commit_approval_rejects_non_calendar_request(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _config()
    config["principals"]["telegram:employee"]["relationship"] = "assistant"
    config["policies"]["assistant"] = {
        "tools": {"allow": ["calendar_commit"]},
        "resources": {"calendar": {"write": "allow"}},
    }
    request = create_approval_request(
        action_type="send_message",
        payload={
            "target": "telegram:12345",
            "message": "Approved reply",
            "owner_id": "owner",
        },
        risk="medium",
        summary="Send message to telegram:12345",
        requester="telegram:employee",
        subject_owner_id="owner",
    )
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)
    try:
        result = json.loads(
            calendar_commit_tool({
                "approval_request_id": request["id"],
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is False
    assert result["error"] == "wrong_action_type"
    assert result["action_type"] == "send_message"
    store = json.loads((tmp_path / "owner_approvals" / "requests.json").read_text())
    assert store["requests"][0]["status"] == "pending"
