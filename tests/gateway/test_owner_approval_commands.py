import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from gateway.config import GatewayConfig, HomeChannel, Platform, PlatformConfig
from gateway.owner_audit import append_audit_event, audit_log_path, read_recent_audit_events
from gateway.owner_approvals import (
    approve_request,
    approval_store_path,
    calendar_events_path,
    create_approval_request,
    create_memory_migration_request,
)
from gateway.permissions import PermissionResolver
from gateway.permissions import reset_current_permission_context, set_current_permission_context
from gateway.platforms.base import MessageEvent
from gateway.session import SessionSource
from tools.memory_tool import ENTRY_DELIMITER, MemoryStore


def _config():
    return {
        "owners": {
            "owner": {
                "principals": ["telegram:owner"],
                "default_correspondent_policy": "coworker",
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


def _make_source(user_id: str) -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        user_id=user_id,
        chat_id=f"chat-{user_id}",
        user_name=user_id,
        chat_type="dm",
    )


def _make_event(text: str, user_id: str = "owner") -> MessageEvent:
    return MessageEvent(
        text=text,
        source=_make_source(user_id),
        message_id="m1",
    )


def _make_runner():
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(
        platforms={Platform.TELEGRAM: PlatformConfig(enabled=True, token="***")}
    )
    adapter = MagicMock()
    adapter.send = AsyncMock()
    runner.adapters = {Platform.TELEGRAM: adapter}
    runner._voice_mode = {}
    runner.hooks = SimpleNamespace(emit=AsyncMock(), emit_collect=AsyncMock(return_value=[]), loaded_hooks=False)
    runner.session_store = MagicMock()
    runner._running_agents = {}
    runner._pending_messages = {}
    runner._pending_approvals = {}
    runner._background_tasks = set()
    runner._session_db = None
    runner._reasoning_config = None
    runner._provider_routing = {}
    runner._fallback_model = None
    runner._show_reasoning = False
    runner._is_user_authorized = lambda _source: True
    runner._set_session_env = lambda _context: None
    return runner


def _make_slash_gated_runner():
    runner = _make_runner()
    runner.config = GatewayConfig(
        platforms={
            Platform.TELEGRAM: PlatformConfig(
                enabled=True,
                token="***",
                extra={"allow_admin_from": ["someone-else"]},
            )
        }
    )
    return runner


def _create_calendar_request():
    return create_approval_request(
        action_type="calendar_request",
        payload={
            "owner_id": "owner",
            "summary": "Planning",
            "start": "2026-06-01T12:00:00Z",
            "end": "2026-06-01T12:30:00Z",
            "attendees": ["alice@example.com"],
        },
        risk="medium",
        summary="Calendar request: Planning",
        requester="telegram:employee",
        subject_owner_id="owner",
        requester_context={
            "platform": "telegram",
            "relationship": "coworker",
            "session_key": "telegram:chat-employee:employee",
        },
    )


def _external_calendar_config():
    config = _config()
    config["owners"]["owner"]["calendar"] = {
        "provider": "google_workspace",
        "external_commit": True,
        "calendar_id": "primary",
    }
    return config


def _write_legacy_user_memory(tmp_path, entries):
    memory_dir = tmp_path / "memories"
    memory_dir.mkdir(parents=True, exist_ok=True)
    (memory_dir / "USER.md").write_text(ENTRY_DELIMITER.join(entries), encoding="utf-8")


def _owner_memory_entries(owner_id: str = "owner"):
    store = MemoryStore(owner_namespace=owner_id, use_owner_memory=True)
    return MemoryStore._read_file(store._path_for("memory"))


@pytest.mark.asyncio
async def test_approvals_lists_pending_owner_requests(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    request = _create_calendar_request()

    result = await _make_runner()._handle_approvals_command(_make_event("/approvals"))

    assert "Pending owner approvals" in result
    assert request["id"] in result
    assert "Calendar request: Planning" in result
    assert "`telegram:employee`" in result


@pytest.mark.asyncio
async def test_audit_command_lists_owner_events(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    append_audit_event(
        subject_owner_id="owner",
        event_type="tool_call",
        requester="telegram:employee",
        session_key="s",
        platform="telegram",
        details={"tool_name": "calendar_request", "decision": "allow"},
    )

    result = await _make_runner()._handle_audit_command(_make_event("/audit 5"))

    assert "Recent owner audit events" in result
    assert "`tool_call`" in result
    assert "tool_name=calendar_request" in result
    assert "decision=allow" in result


@pytest.mark.asyncio
async def test_audit_command_is_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)

    result = await _make_runner()._handle_audit_command(
        _make_event("/audit", user_id="employee")
    )

    assert "owner-only" in result


@pytest.mark.asyncio
async def test_permissions_command_shows_target_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)

    result = await _make_runner()._handle_permissions_command(
        _make_event("/permissions telegram:employee")
    )

    assert "Permissions for `telegram:employee`" in result
    assert "Subject owner: `owner`" in result
    assert "Relationship: `coworker`" in result
    assert "Allowed tools: `calendar_request`, `owner_availability`" in result


@pytest.mark.asyncio
async def test_permissions_command_is_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)

    result = await _make_runner()._handle_permissions_command(
        _make_event("/permissions telegram:owner", user_id="employee")
    )

    assert "owner-only" in result


@pytest.mark.asyncio
async def test_approvals_are_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    _create_calendar_request()

    result = await _make_runner()._handle_approvals_command(
        _make_event("/approvals", user_id="employee")
    )

    assert "owner-only" in result


def test_owner_policy_bypasses_legacy_slash_gate(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    runner = _make_slash_gated_runner()

    assert runner._check_slash_access(_make_source("owner"), "restart") is None
    assert "admin-only" in runner._check_slash_access(_make_source("employee"), "restart")


@pytest.mark.asyncio
async def test_users_set_updates_principal_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run
    from utils import atomic_yaml_write

    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    atomic_yaml_write(tmp_path / "config.yaml", _config())

    result = await _make_runner()._handle_users_command(
        _make_event("/users set telegram:newhire guest owner")
    )

    assert "Updated `telegram:newhire`" in result
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert saved["principals"]["telegram:newhire"] == {
        "relationship": "guest",
        "subject_owner": "owner",
    }

    audit_events = read_recent_audit_events("owner", limit=5)
    assert audit_events[-1]["event_type"] == "principal_policy_updated"
    assert audit_events[-1]["details"]["target_principal"] == "telegram:newhire"


@pytest.mark.asyncio
async def test_users_command_is_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)

    result = await _make_runner()._handle_users_command(
        _make_event("/users set telegram:newhire guest owner", user_id="employee")
    )

    assert "owner-only" in result


@pytest.mark.asyncio
async def test_approve_owner_request_commits_local_calendar_event(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    request = _create_calendar_request()

    result = await _make_runner()._handle_approve_command(
        _make_event(f"/approve {request['id']}")
    )

    assert f"Approved `{request['id']}`" in result
    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    updated = store["requests"][0]
    assert updated["status"] == "approved"
    assert updated["approved_by"] == "telegram:owner"
    assert updated["execution_result"]["status"] == "committed_local"

    events = json.loads(calendar_events_path().read_text(encoding="utf-8"))
    event = events["events"][0]
    assert event["approval_request_id"] == request["id"]
    assert event["summary"] == "Planning"
    assert event["external_effect"] == "none"

    audit_events = read_recent_audit_events("owner", limit=5)
    assert [event["event_type"] for event in audit_events] == [
        "approval_requested",
        "calendar_committed",
        "approval_approved",
    ]


def test_approve_calendar_request_commits_external_provider_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _external_calendar_config()
    calls = []

    def _fake_google_create(payload, provider_config):
        calls.append((dict(payload), dict(provider_config)))
        return {
            "success": True,
            "provider": "google_workspace",
            "external_event_id": "gcal-123",
            "html_link": "https://calendar.example/gcal-123",
        }

    monkeypatch.setattr("hermes_cli.config.load_config", lambda: config)
    monkeypatch.setattr(
        "gateway.owner_approvals._create_google_workspace_calendar_event",
        _fake_google_create,
    )

    request = _create_calendar_request()
    assert calls == []

    result = approve_request(
        request["id"],
        owner_principal="telegram:owner",
        owner_ids={"owner"},
    )

    assert result["success"] is True
    assert result["execution_result"]["status"] == "committed_external"
    assert result["execution_result"]["external_effect"] == "calendar_create"
    assert result["execution_result"]["external_provider"] == "google_workspace"
    assert result["execution_result"]["external_event_id"] == "gcal-123"
    assert calls == [
        (
            request["proposed_payload"],
            {
                "enabled": True,
                "provider": "google_workspace",
                "calendar_id": "primary",
            },
        )
    ]

    events = json.loads(calendar_events_path().read_text(encoding="utf-8"))
    event = events["events"][0]
    assert event["status"] == "committed_external"
    assert event["external_effect"] == "calendar_create"
    assert event["external_provider"] == "google_workspace"
    assert event["external_event_id"] == "gcal-123"
    assert event["external_link"] == "https://calendar.example/gcal-123"


def test_approve_calendar_request_records_external_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config = _external_calendar_config()

    def _fake_google_create(payload, provider_config):
        return {
            "success": False,
            "provider": "google_workspace",
            "error": "calendar API unavailable",
        }

    monkeypatch.setattr("hermes_cli.config.load_config", lambda: config)
    monkeypatch.setattr(
        "gateway.owner_approvals._create_google_workspace_calendar_event",
        _fake_google_create,
    )
    request = _create_calendar_request()

    result = approve_request(
        request["id"],
        owner_principal="telegram:owner",
        owner_ids={"owner"},
    )

    assert result["success"] is True
    assert result["execution_result"]["status"] == "external_failed"
    assert result["execution_result"]["external_effect"] == "none"
    assert result["execution_result"]["error"] == "calendar API unavailable"
    events = json.loads(calendar_events_path().read_text(encoding="utf-8"))
    event = events["events"][0]
    assert event["status"] == "external_failed"
    assert event["external_effect"] == "none"
    assert event["external_provider"] == "google_workspace"
    assert event["external_error"] == "calendar API unavailable"


@pytest.mark.asyncio
async def test_memory_migrate_creates_owner_confirmation_request(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    _write_legacy_user_memory(tmp_path, ["Owner prefers concise summaries"])

    result = await _make_runner()._handle_memory_migrate_command(
        _make_event("/memory-migrate")
    )

    assert "Created owner memory migration approval" in result
    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    request = store["requests"][0]
    assert request["status"] == "pending"
    assert request["action_type"] == "memory_migration"
    assert request["subject_owner_id"] == "owner"
    assert request["proposed_payload"]["entry_count"] == 1
    assert _owner_memory_entries() == []


@pytest.mark.asyncio
async def test_approve_memory_migration_copies_legacy_user_memory(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    legacy_entries = [
        "Owner prefers concise summaries",
        "Owner timezone is UTC",
    ]
    _write_legacy_user_memory(tmp_path, legacy_entries)

    create_result = await _make_runner()._handle_memory_migrate_command(
        _make_event("/memory-migrate")
    )
    request_id = json.loads(approval_store_path().read_text(encoding="utf-8"))["requests"][0]["id"]

    assert f"/approve {request_id}" in create_result

    result = await _make_runner()._handle_approve_command(
        _make_event(f"/approve {request_id}")
    )

    assert f"Approved `{request_id}`" in result
    assert "Migrated 2 legacy USER.md entries" in result
    assert _owner_memory_entries() == legacy_entries
    assert (tmp_path / "memories" / "USER.md").exists()

    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    updated = store["requests"][0]
    assert updated["status"] == "approved"
    assert updated["execution_result"]["status"] == "migrated"
    assert updated["execution_result"]["copied_count"] == 2

    audit_events = read_recent_audit_events("owner", limit=5)
    assert [event["event_type"] for event in audit_events] == [
        "approval_requested",
        "memory_migrated",
        "approval_approved",
    ]


def test_memory_migration_preserves_existing_owner_memory(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _write_legacy_user_memory(
        tmp_path,
        [
            "Owner prefers concise summaries",
            "Owner timezone is UTC",
        ],
    )
    owner_store = MemoryStore(owner_namespace="owner", use_owner_memory=True)
    owner_store.memory_entries = ["Owner prefers concise summaries", "Existing owner note"]
    owner_store.save_to_disk("memory")

    request_result = create_memory_migration_request(
        subject_owner_id="owner",
        requester="telegram:owner",
    )
    result = approve_request(
        request_result["request"]["id"],
        owner_principal="telegram:owner",
        owner_ids={"owner"},
    )

    assert result["success"] is True
    assert result["execution_result"]["status"] == "migrated"
    assert result["execution_result"]["copied_count"] == 1
    assert _owner_memory_entries() == [
        "Owner prefers concise summaries",
        "Existing owner note",
        "Owner timezone is UTC",
    ]


@pytest.mark.asyncio
async def test_owner_approval_notification_sends_to_owner_home_channel(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    runner = _make_runner()
    runner.config.platforms[Platform.TELEGRAM].home_channel = HomeChannel(
        platform=Platform.TELEGRAM,
        chat_id="owner-home",
        name="Owner Home",
        thread_id="topic-1",
    )
    adapter = runner.adapters[Platform.TELEGRAM]
    adapter.send = AsyncMock(return_value=SimpleNamespace(success=True))
    request = _create_calendar_request()

    delivered = await runner._send_owner_approval_notification(
        request,
        config_data=_config(),
    )

    assert delivered == 1
    adapter.send.assert_awaited_once()
    args, kwargs = adapter.send.await_args
    assert args[:2] == ("owner-home", runner._format_owner_approval_notification(request))
    assert kwargs["metadata"] == {"thread_id": "topic-1"}
    assert request["id"] in args[1]
    assert "/approve" in args[1]


@pytest.mark.asyncio
async def test_deny_memory_migration_leaves_owner_memory_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    _write_legacy_user_memory(tmp_path, ["Owner prefers concise summaries"])
    request = create_memory_migration_request(
        subject_owner_id="owner",
        requester="telegram:owner",
    )["request"]

    result = await _make_runner()._handle_deny_command(
        _make_event(f"/deny {request['id']} not now")
    )

    assert f"Denied `{request['id']}`" in result
    assert _owner_memory_entries() == []
    assert (tmp_path / "memories" / "USER.md").exists()


@pytest.mark.asyncio
async def test_deny_owner_request_records_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from gateway import run as gateway_run

    monkeypatch.setattr(gateway_run, "_load_gateway_config", _config)
    request = _create_calendar_request()

    result = await _make_runner()._handle_deny_command(
        _make_event(f"/deny {request['id']} double booked")
    )

    assert f"Denied `{request['id']}`" in result
    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    updated = store["requests"][0]
    assert updated["status"] == "denied"
    assert updated["denied_by"] == "telegram:owner"
    assert updated["denial_reason"] == "double booked"
    assert updated["safe_response"] == "The owner declined this request: double booked"

    audit_events = read_recent_audit_events("owner", limit=5)
    assert [event["event_type"] for event in audit_events] == [
        "approval_requested",
        "approval_denied",
    ]


def test_tool_policy_denial_writes_owner_audit(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from model_tools import handle_function_call

    ctx = PermissionResolver(_config()).resolve(_make_source("employee"), session_key="s")

    result = json.loads(
        handle_function_call(
            "terminal",
            {"command": "echo secret"},
            enabled_tools=["calendar_request"],
            tool_policy_context=ctx,
            task_id="task-1",
            session_id="session-1",
        )
    )

    assert "error" in result
    audit_events = read_recent_audit_events("owner", limit=5)
    assert len(audit_events) == 1
    event = audit_events[0]
    assert event["event_type"] == "tool_call"
    assert event["requester"] == "telegram:employee"
    assert event["details"]["tool_name"] == "terminal"
    assert event["details"]["decision"] == "deny"
    assert event["details"]["arg_keys"] == ["command"]


def test_send_message_ask_owner_dispatch_creates_approval(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from model_tools import handle_function_call

    config = _config()
    config["policies"]["coworker"]["tools"]["ask_owner"] = ["send_message"]
    ctx = PermissionResolver(config).resolve(_make_source("employee"), session_key="s")

    result = json.loads(
        handle_function_call(
            "send_message",
            {"action": "send", "target": "telegram:friend", "message": "Could you review this?"},
            enabled_tools=["owner_availability"],
            tool_policy_context=ctx,
            task_id="task-1",
            session_id="session-1",
        )
    )

    assert result["success"] is True
    assert result["approval_required"] is True
    assert result["external_effect"] == "none"
    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    request = store["requests"][0]
    assert request["id"] == result["approval_request_id"]
    assert request["action_type"] == "send_message"
    assert request["requester"] == "telegram:employee"
    assert request["subject_owner_id"] == "owner"
    assert request["proposed_payload"] == {
        "message": "Could you review this?",
        "owner_id": "owner",
        "target": "telegram:friend",
    }

    audit_events = read_recent_audit_events("owner", limit=5)
    assert [event["event_type"] for event in audit_events] == [
        "approval_requested",
        "tool_call",
    ]
    assert audit_events[-1]["details"]["decision"] == "ask_owner"


def test_send_message_tool_creates_approval_instead_of_sending_for_correspondent(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from tools.send_message_tool import send_message_tool

    config = _config()
    ctx = PermissionResolver(config).resolve(_make_source("employee"), session_key="s")
    token = set_current_permission_context(ctx)
    try:
        result = json.loads(
            send_message_tool({
                "action": "send",
                "target": "telegram:friend",
                "message": "Could you review this?",
            })
        )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    assert result["approval_required"] is True
    assert result["external_effect"] == "none"
    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    request = store["requests"][0]
    assert request["action_type"] == "send_message"
    assert request["proposed_payload"]["target"] == "telegram:friend"
    assert request["proposed_payload"]["message"] == "Could you review this?"


def test_send_message_tool_allows_explicit_delegated_messaging(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from tools.send_message_tool import send_message_tool

    config_data = _config()
    config_data["policies"]["coworker"] = {
        "tools": {"allow": ["send_message"]},
        "resources": {
            "messaging": {
                "send": "allow",
                "targets": ["telegram:*"],
            }
        },
    }
    ctx = PermissionResolver(config_data).resolve(_make_source("employee"), session_key="s")
    runner = _make_runner()
    telegram_cfg = runner.config.platforms[Platform.TELEGRAM]
    token = set_current_permission_context(ctx)
    try:
        with monkeypatch.context() as m:
            m.setattr("gateway.config.load_gateway_config", lambda: runner.config)
            m.setattr("tools.interrupt.is_interrupted", lambda: False)
            send_mock = AsyncMock(return_value={"success": True, "message_id": "msg-1"})
            m.setattr("tools.send_message_tool._send_to_platform", send_mock)
            m.setattr("model_tools._run_async", lambda coro: asyncio.run(coro))
            m.setattr("gateway.mirror.mirror_to_session", lambda *args, **kwargs: False)
            result = json.loads(
                send_message_tool({
                    "action": "send",
                    "target": "telegram:12345",
                    "message": "Low-risk delegated reply",
                })
            )
    finally:
        reset_current_permission_context(token)

    assert result["success"] is True
    send_mock.assert_awaited_once_with(
        Platform.TELEGRAM,
        telegram_cfg,
        "12345",
        "Low-risk delegated reply",
        thread_id=None,
        media_files=[],
        force_document=False,
    )
    assert not approval_store_path().exists()


def test_approve_send_message_request_executes_held_send(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    runner = _make_runner()
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
    send_mock = AsyncMock(return_value={"success": True, "message_id": "msg-1"})

    monkeypatch.setattr("gateway.config.load_gateway_config", lambda: runner.config)
    monkeypatch.setattr("tools.interrupt.is_interrupted", lambda: False)
    monkeypatch.setattr("tools.send_message_tool._send_to_platform", send_mock)
    monkeypatch.setattr("model_tools._run_async", lambda coro: asyncio.run(coro))
    monkeypatch.setattr("gateway.mirror.mirror_to_session", lambda *args, **kwargs: False)

    result = approve_request(
        request["id"],
        owner_principal="telegram:owner",
        owner_ids={"owner"},
    )

    assert result["success"] is True
    assert result["execution_result"]["status"] == "sent"
    assert result["execution_result"]["external_effect"] == "message_send"
    send_mock.assert_awaited_once()
    store = json.loads(approval_store_path().read_text(encoding="utf-8"))
    assert store["requests"][0]["status"] == "approved"
    assert store["requests"][0]["execution_result"]["send_result"]["message_id"] == "msg-1"


def test_owner_audit_redacts_sensitive_detail_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    append_audit_event(
        subject_owner_id="owner",
        event_type="secret_test",
        requester="telegram:owner",
        details={"api_key": "sk-should-not-appear", "safe": "visible"},
    )

    raw = audit_log_path("owner").read_text(encoding="utf-8")
    assert "sk-should-not-appear" not in raw
    event = read_recent_audit_events("owner", limit=1)[0]
    assert event["details"]["api_key"] == "[REDACTED]"
    assert event["details"]["safe"] == "visible"
