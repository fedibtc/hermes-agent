from gateway.config import Platform
from gateway.permissions import PermissionResolver
from gateway.principals import PrincipalResolver
from gateway.session import SessionSource


CONFIG = {
    "owners": {
        "tav": {
            "principals": ["telegram:owner-1", "slack:UOWNER"],
            "default_correspondent_policy": "coworker",
        }
    },
    "principals": {
        "telegram:employee-1": {
            "relationship": "coworker",
            "subject_owner": "tav",
        },
        "telegram:blocked-1": {
            "relationship": "blocked",
            "subject_owner": "tav",
        },
    },
    "policies": {
        "coworker": {
            "tools": {
                "allow": ["clarify", "web_*", "owner_availability"],
                "ask_owner": ["send_message"],
                "deny": ["terminal", "memory", "session_search"],
            },
            "resources": {
                "calendar": {"read": "freebusy", "write": "ask_owner"},
            },
        }
    },
}


def _source(user_id: str) -> SessionSource:
    return SessionSource(
        platform=Platform.TELEGRAM,
        chat_id="chat-1",
        chat_type="dm",
        user_id=user_id,
        user_name=user_id,
    )


def test_owner_gets_all_tools():
    ctx = PermissionResolver(CONFIG).resolve(_source("owner-1"), session_key="s")

    assert ctx is not None
    assert ctx.is_owner is True
    assert ctx.subject_owner_id == "tav"
    assert ctx.allows_tool_name("terminal") is True
    assert ctx.allows_tool_name("memory") is True


def test_correspondent_gets_policy_filtered_tools():
    ctx = PermissionResolver(CONFIG).resolve(_source("employee-1"), session_key="s")

    assert ctx is not None
    assert ctx.is_owner is False
    assert ctx.relationship == "coworker"
    assert ctx.subject_owner_id == "tav"
    assert ctx.allows_tool_name("web_search") is True
    assert ctx.allows_tool_name("owner_availability") is True
    assert ctx.allows_tool_name("terminal") is False
    assert ctx.allows_tool_name("memory") is False
    assert ctx.allows_tool_name("send_message") is False
    assert ctx.tool_decision("send_message") == "ask_owner"
    assert "requires owner approval" in ctx.tool_denial_message("send_message")


def test_configured_principal_alias_resolves_to_canonical_key():
    cfg = {
        **CONFIG,
        "principals": {
            **CONFIG["principals"],
            "slack:UEMPLOYEE": {
                "relationship": "coworker",
                "subject_owner": "tav",
                "aliases": ["telegram:employee-alias"],
            },
        },
    }

    principal = PrincipalResolver(cfg).resolve(_source("employee-alias"))
    ctx = PermissionResolver(cfg).resolve(_source("employee-alias"), session_key="s")

    assert principal.key == "slack:UEMPLOYEE"
    assert "telegram:employee-alias" in principal.aliases
    assert ctx is not None
    assert ctx.requester.key == "slack:UEMPLOYEE"
    assert ctx.allows_tool_name("web_search") is True


def test_unknown_user_in_single_owner_config_gets_default_correspondent_policy():
    ctx = PermissionResolver(CONFIG).resolve(_source("new-employee"), session_key="s")

    assert ctx is not None
    assert ctx.relationship == "coworker"
    assert ctx.subject_owner_id == "tav"
    assert ctx.allows_tool_name("clarify") is True
    assert ctx.allows_tool_name("terminal") is False


def test_blocked_principal_fails_closed():
    ctx = PermissionResolver(CONFIG).resolve(_source("blocked-1"), session_key="s")

    assert ctx is not None
    assert ctx.relationship == "blocked"
    assert ctx.filter_tool_names(["clarify", "web_search", "terminal"]) == frozenset()


def test_policy_error_context_fails_closed():
    ctx = PermissionResolver(CONFIG).fail_closed_context(_source("employee-1"), session_key="s")

    assert ctx.relationship == "blocked"
    assert ctx.policy_name == "policy_error"
    assert ctx.subject_owner_id == "tav"
    assert ctx.filter_tool_names(["clarify", "web_search", "terminal"]) == frozenset()
    assert "Tool access: restricted" in ctx.prompt_block()


def test_mcp_policy_hides_owner_private_servers_from_correspondents():
    cfg = {
        **CONFIG,
        "policies": {
            **CONFIG["policies"],
            "coworker": {"tools": {"allow": ["mcp_*"]}},
        },
        "mcp_policy": {
            "owner_private": {"visible_to": ["owner"]},
            "shared_readonly": {"visible_to": ["owner", "coworker"]},
        },
        "mcp_servers": {
            "owner-files": {"policy": "owner_private", "command": "owner-mcp"},
            "shared-docs": {"policy": "shared_readonly", "command": "shared-mcp"},
        },
    }

    ctx = PermissionResolver(cfg).resolve(_source("employee-1"), session_key="s")

    assert ctx is not None
    assert ctx.allows_tool_name("mcp_shared_docs_search") is True
    assert ctx.allows_tool_name("mcp_owner_files_read") is False
    assert set(ctx.filter_mcp_servers(cfg["mcp_servers"])) == {"shared-docs"}


def test_mcp_requester_scoped_server_requires_and_applies_requester_overlay():
    cfg = {
        **CONFIG,
        "policies": {
            **CONFIG["policies"],
            "coworker": {"tools": {"allow": ["mcp_*"]}},
        },
        "mcp_policy": {
            "requester_scoped": {
                "visible_to": ["owner", "coworker"],
                "credential_source": "requester",
            },
        },
        "mcp_servers": {
            "employee-api": {
                "policy": "requester_scoped",
                "url": "https://mcp.example.test",
                "headers": {"X-Base": "1", "Authorization": "Bearer owner"},
                "env": {"PATH": "/usr/bin", "OWNER_API_KEY": "owner"},
                "requester_credentials": {
                    "telegram:employee-1": {
                        "headers": {"Authorization": "Bearer employee"},
                        "env": {"EMPLOYEE_TOKEN": "employee"},
                    },
                },
            },
        },
    }

    employee_ctx = PermissionResolver(cfg).resolve(_source("employee-1"), session_key="s")
    unknown_ctx = PermissionResolver(cfg).resolve(_source("new-employee"), session_key="s")

    assert employee_ctx is not None
    projected = employee_ctx.filter_mcp_servers(cfg["mcp_servers"])
    assert set(projected) == {"employee-api"}
    assert projected["employee-api"]["headers"] == {
        "X-Base": "1",
        "Authorization": "Bearer employee",
    }
    assert projected["employee-api"]["env"] == {
        "PATH": "/usr/bin",
        "EMPLOYEE_TOKEN": "employee",
    }
    assert "requester_credentials" not in projected["employee-api"]
    assert employee_ctx.allows_tool_name("mcp_employee_api_lookup") is True

    assert unknown_ctx is not None
    assert unknown_ctx.filter_mcp_servers(cfg["mcp_servers"]) == {}
    assert unknown_ctx.allows_tool_name("mcp_employee_api_lookup") is False


def test_absent_policy_config_preserves_legacy_behavior():
    assert PermissionResolver({}).resolve(_source("anyone"), session_key="s") is None
