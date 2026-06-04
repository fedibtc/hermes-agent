"""Owner/correspondent policy core for Hermes gateway turns.

This module is deliberately deterministic.  It does not ask the model to
decide what is allowed; it resolves a policy context from config and exposes
helpers for filtering tool names before the model sees schemas and again at
dispatch.
"""

from __future__ import annotations

import contextvars
import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Literal, Mapping

from gateway.principals import Principal, PrincipalResolver, normalize_principal_key, platform_name


PolicyAction = Literal["allow", "deny", "ask_owner", "ask_requester"]

_current_permission_context: contextvars.ContextVar["PermissionContext | None"] = contextvars.ContextVar(
    "gateway_permission_context",
    default=None,
)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)]


def _normalize_patterns(value: Any) -> frozenset[str]:
    return frozenset(v.strip() for v in _as_list(value) if v.strip())


def _matches(patterns: Iterable[str], tool_name: str) -> bool:
    return any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in patterns)


def _sanitize_mcp_name_component(value: str) -> str:
    """Mirror MCP tool-name prefix sanitization without importing tools."""

    return re.sub(r"[^A-Za-z0-9_]", "_", str(value or ""))


def _merge_mapping(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge overlay into base for MCP env/header projections."""

    merged: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _merge_mapping(merged[key], value)
        else:
            merged[key] = value
    return merged


def _strip_mcp_policy_keys(server_cfg: Mapping[str, Any]) -> dict[str, Any]:
    """Remove policy-only keys before handing config to MCP transport code."""

    out = dict(server_cfg)
    for key in (
        "access",
        "credential_source",
        "mcp_policy",
        "policy",
        "policy_profile",
        "principal_overlays",
        "requester_credentials",
        "visibility",
        "visible_to",
    ):
        out.pop(key, None)
    return out


def _drop_mcp_credential_material(server_cfg: Mapping[str, Any]) -> dict[str, Any]:
    """Drop obvious owner credential material before requester overlays."""

    out = dict(server_cfg)
    out.pop("auth", None)
    out.pop("oauth", None)

    sensitive_names = ("authorization", "api-key", "apikey", "cookie")
    sensitive_fragments = ("api_key", "apikey", "auth", "token", "secret", "password", "credential", "private_key")

    headers = _as_mapping(out.get("headers"))
    if headers:
        out["headers"] = {
            key: value
            for key, value in headers.items()
            if (
                str(key).strip().lower() not in sensitive_names
                and not any(fragment in str(key).strip().lower() for fragment in sensitive_fragments)
            )
        }

    env = _as_mapping(out.get("env"))
    if env:
        out["env"] = {
            key: value
            for key, value in env.items()
            if not any(fragment in str(key).strip().lower() for fragment in sensitive_fragments)
        }

    return out


@dataclass(frozen=True)
class ToolRule:
    pattern: str
    action: PolicyAction
    resources: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class ResourceRule:
    resource: str
    read: str = "deny"
    write: str = "deny"


def set_current_permission_context(context: "PermissionContext | None") -> contextvars.Token:
    """Bind the effective gateway policy context to this execution context."""

    return _current_permission_context.set(context)


def reset_current_permission_context(token: contextvars.Token) -> None:
    """Restore the previous gateway policy context."""

    _current_permission_context.reset(token)


def get_current_permission_context() -> "PermissionContext | None":
    """Return the current gateway policy context, if any."""

    return _current_permission_context.get()


@dataclass(frozen=True)
class PermissionContext:
    requester: Principal
    subject_owner_id: str
    platform: str
    scope: Literal["dm", "group", "thread", "channel"]
    session_key: str
    relationship: str
    policy_name: str
    tool_allow_patterns: frozenset[str] = field(default_factory=frozenset)
    tool_deny_patterns: frozenset[str] = field(default_factory=frozenset)
    tool_ask_owner_patterns: frozenset[str] = field(default_factory=frozenset)
    resource_rules: Mapping[str, Any] = field(default_factory=dict)
    mcp_policy: Mapping[str, Any] = field(default_factory=dict)
    mcp_visible_tool_patterns: frozenset[str] = field(default_factory=frozenset)
    mcp_visibility_active: bool = False
    mcp_projection_signature: str = ""
    policy_active: bool = True

    @property
    def is_owner(self) -> bool:
        return self.relationship == "owner" or self.subject_owner_id in self.requester.owner_ids

    @property
    def session_user_id(self) -> str:
        return self.requester.key

    @property
    def session_search_user_id(self) -> str | None:
        return None if self.is_owner else self.requester.key

    @property
    def session_search_subject_owner_id(self) -> str | None:
        return self.subject_owner_id or None

    @property
    def session_search_visibility(self) -> tuple[str, ...] | None:
        if self.is_owner:
            return None
        requester = self.requester.key
        return (
            "correspondent_private",
            "shared",
            f"shared:{requester}",
        )

    @property
    def session_search_shared_visibility(self) -> tuple[str, ...] | None:
        if self.is_owner:
            return None
        requester = self.requester.key
        return (
            "shared",
            f"shared:{requester}",
        )

    @property
    def session_visibility(self) -> str:
        return "owner_private" if self.is_owner else "correspondent_private"

    def allows_tool_name(self, tool_name: str) -> bool:
        return self.tool_decision(tool_name) == "allow"

    def tool_decision(self, tool_name: str) -> PolicyAction:
        if not self.policy_active:
            return "allow"
        if not tool_name:
            return "deny"
        if (
            tool_name.startswith("mcp_")
            and self.mcp_visibility_active
            and not _matches(self.mcp_visible_tool_patterns, tool_name)
        ):
            return "deny"
        if _matches(self.tool_deny_patterns, tool_name):
            return "deny"
        if _matches(self.tool_ask_owner_patterns, tool_name):
            return "ask_owner"
        if _matches(self.tool_allow_patterns, "*"):
            return "allow"
        return "allow" if _matches(self.tool_allow_patterns, tool_name) else "deny"

    def tool_denial_message(self, tool_name: str) -> str:
        decision = self.tool_decision(tool_name)
        if decision == "ask_owner":
            return (
                f"Tool '{tool_name}' requires owner approval for requester "
                f"{self.requester.key}. Ask the owner to approve this action "
                "or offer a safe alternative."
            )
        return (
            f"Tool '{tool_name}' is not enabled for requester {self.requester.key} "
            f"under policy '{self.policy_name}'. Offer a safe alternative or ask "
            "the owner to delegate the capability."
        )

    def filter_tool_names(self, tool_names: Iterable[str]) -> frozenset[str]:
        # Keep tools the policy allows outright *and* tools gated behind owner
        # approval. ask_owner tools must stay in the schema so the model can
        # call them and trigger the durable approval path; the executor
        # intercepts the call and creates an approval request instead of
        # running the underlying action. (denied tools are dropped.)
        return frozenset(
            name
            for name in tool_names
            if self.tool_decision(name) in ("allow", "ask_owner")
        )

    def prompt_block(self) -> str:
        if not self.policy_active:
            return ""
        role = "owner" if self.is_owner else self.relationship
        allowed = "all" if "*" in self.tool_allow_patterns and not self.tool_deny_patterns else "restricted"
        return (
            "[Gateway policy]\n"
            f"- Requester principal: {self.requester.key}"
            + (f" ({self.requester.display_name})" if self.requester.display_name else "")
            + "\n"
            f"- Subject owner: {self.subject_owner_id or 'unresolved'}\n"
            f"- Relationship: {role}\n"
            f"- Tool access: {allowed}; tools not exposed in this session are off limits.\n"
            "- Treat owner-private memory, files, calendars, credentials, MCP servers, and transcripts as unavailable unless a tool result explicitly provides policy-approved information.\n"
            "- If a requested action needs owner authority or private data, ask for owner approval or provide a safe alternative."
        )

    def to_transport_dict(self) -> dict[str, Any]:
        """Serialize the resolved policy for cross-process propagation.

        Used when the gateway runs in proxy mode (``GATEWAY_PROXY_URL``): the
        thin relay forwards the already-resolved policy to the remote API
        server so the remote rebuilds a *restricted* agent instead of an
        unrestricted one. Carries only the resolved decision surface — no
        owner credential material (that is stripped during MCP projection).
        """

        return {
            "requester": {
                "key": self.requester.key,
                "display_name": self.requester.display_name,
                "kind": self.requester.kind,
                "owner_ids": sorted(self.requester.owner_ids),
                "aliases": sorted(self.requester.aliases),
            },
            "subject_owner_id": self.subject_owner_id,
            "platform": self.platform,
            "scope": self.scope,
            "session_key": self.session_key,
            "relationship": self.relationship,
            "policy_name": self.policy_name,
            "tool_allow_patterns": sorted(self.tool_allow_patterns),
            "tool_deny_patterns": sorted(self.tool_deny_patterns),
            "tool_ask_owner_patterns": sorted(self.tool_ask_owner_patterns),
            "resource_rules": dict(self.resource_rules),
            "mcp_policy": dict(self.mcp_policy),
            "mcp_visible_tool_patterns": sorted(self.mcp_visible_tool_patterns),
            "mcp_visibility_active": self.mcp_visibility_active,
            "mcp_projection_signature": self.mcp_projection_signature,
            "policy_active": self.policy_active,
        }

    @classmethod
    def from_transport_dict(cls, data: Mapping[str, Any]) -> "PermissionContext":
        """Rebuild a :class:`PermissionContext` produced by
        :meth:`to_transport_dict`. Unknown/missing fields degrade safely."""

        data = _as_mapping(data)
        requester_raw = _as_mapping(data.get("requester"))
        requester = Principal(
            key=str(requester_raw.get("key") or "unknown"),
            display_name=str(requester_raw.get("display_name") or ""),
            kind=str(requester_raw.get("kind") or "human"),
            owner_ids=frozenset(_as_list(requester_raw.get("owner_ids"))),
            aliases=frozenset(_as_list(requester_raw.get("aliases"))),
        )
        scope = str(data.get("scope") or "dm")
        if scope not in ("dm", "group", "thread", "channel"):
            scope = "dm"
        return cls(
            requester=requester,
            subject_owner_id=str(data.get("subject_owner_id") or ""),
            platform=str(data.get("platform") or ""),
            scope=scope,  # type: ignore[arg-type]
            session_key=str(data.get("session_key") or ""),
            relationship=str(data.get("relationship") or ""),
            policy_name=str(data.get("policy_name") or ""),
            tool_allow_patterns=_normalize_patterns(data.get("tool_allow_patterns")),
            tool_deny_patterns=_normalize_patterns(data.get("tool_deny_patterns")),
            tool_ask_owner_patterns=_normalize_patterns(data.get("tool_ask_owner_patterns")),
            resource_rules=_as_mapping(data.get("resource_rules")),
            mcp_policy=_as_mapping(data.get("mcp_policy")),
            mcp_visible_tool_patterns=_normalize_patterns(data.get("mcp_visible_tool_patterns")),
            mcp_visibility_active=bool(data.get("mcp_visibility_active")),
            mcp_projection_signature=str(data.get("mcp_projection_signature") or ""),
            policy_active=bool(data.get("policy_active", True)),
        )

    def signature(self) -> str:
        payload = {
            "requester": self.requester.key,
            "owner": self.subject_owner_id,
            "relationship": self.relationship,
            "policy": self.policy_name,
            "allow": sorted(self.tool_allow_patterns),
            "deny": sorted(self.tool_deny_patterns),
            "ask_owner": sorted(self.tool_ask_owner_patterns),
            "mcp_visible": sorted(self.mcp_visible_tool_patterns),
            "mcp_visibility_active": self.mcp_visibility_active,
            "mcp_projection": self.mcp_projection_signature,
        }
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _mcp_visibility_tokens(self) -> set[str]:
        tokens = {"*", "all"}
        if self.is_owner:
            tokens.update({"owner", "owners"})
        else:
            tokens.update({"correspondent", "correspondents", "authenticated"})
            if self.relationship:
                tokens.add(self.relationship)
            if self.policy_name:
                tokens.add(self.policy_name)
        return tokens

    def _mcp_server_policy(self, server_name: str, server_cfg: Mapping[str, Any]) -> Mapping[str, Any]:
        policy_profiles = _as_mapping(self.mcp_policy)
        profile_name = str(
            server_cfg.get("policy")
            or server_cfg.get("policy_profile")
            or server_cfg.get("mcp_policy")
            or server_cfg.get("visibility")
            or ""
        )
        profile = _as_mapping(policy_profiles.get(profile_name))
        return _merge_mapping(profile, server_cfg)

    def mcp_server_visible(self, server_name: str, server_cfg: Mapping[str, Any]) -> bool:
        if not self.policy_active:
            return True
        policy = self._mcp_server_policy(server_name, server_cfg)
        visible_to = _normalize_patterns(policy.get("visible_to"))
        if visible_to and not (visible_to & self._mcp_visibility_tokens()):
            return False
        credential_source = str(policy.get("credential_source") or "").strip().lower()
        if credential_source == "requester" and not self.is_owner:
            overlays = _as_mapping(policy.get("requester_credentials")) or _as_mapping(policy.get("principal_overlays"))
            if not _as_mapping(overlays.get(self.requester.key)):
                return False
        return True

    def project_mcp_server_config(self, server_name: str, server_cfg: Mapping[str, Any]) -> dict[str, Any]:
        policy = self._mcp_server_policy(server_name, server_cfg)
        projected = _strip_mcp_policy_keys(policy)
        credential_source = str(policy.get("credential_source") or "").strip().lower()
        if credential_source == "requester" and not self.is_owner:
            overlays = _as_mapping(policy.get("requester_credentials")) or _as_mapping(policy.get("principal_overlays"))
            overlay = _as_mapping(overlays.get(self.requester.key))
            projected = _drop_mcp_credential_material(projected)
            projected = _merge_mapping(projected, overlay)
        return projected

    def filter_mcp_servers(self, servers: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        """Return MCP server config visible under this permission context."""

        if not self.policy_active:
            return {
                str(name): dict(cfg)
                for name, cfg in servers.items()
                if isinstance(cfg, Mapping)
            }

        filtered: dict[str, dict[str, Any]] = {}
        for name, cfg in servers.items():
            if not isinstance(cfg, Mapping):
                continue
            server_name = str(name)
            if not self.mcp_server_visible(server_name, cfg):
                continue
            filtered[server_name] = self.project_mcp_server_config(server_name, cfg)
        return filtered


class PermissionResolver:
    """Resolve an effective owner/correspondent policy from config."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config if isinstance(config, Mapping) else {}
        self.principals = PrincipalResolver(self.config)

    def is_configured(self) -> bool:
        return any(
            isinstance(self.config.get(key), Mapping) and bool(self.config.get(key))
            for key in ("owners", "principals")
        )

    def _scope_for_source(self, source: Any) -> Literal["dm", "group", "thread", "channel"]:
        raw = str(getattr(source, "chat_type", "") or "").lower()
        if raw in {"thread"}:
            return "thread"
        if raw in {"channel"}:
            return "channel"
        if raw in {"dm", "direct", "private", ""}:
            return "dm"
        return "group"

    def _principal_block(self, principal: Principal) -> Mapping[str, Any]:
        blocks = _as_mapping(self.config.get("principals"))
        for key in principal.aliases:
            block = blocks.get(key)
            if isinstance(block, Mapping):
                return block
        return {}

    def _single_owner_id(self) -> str:
        owners = _as_mapping(self.config.get("owners"))
        if len(owners) == 1:
            return str(next(iter(owners.keys())))
        return ""

    def _default_policy_for_owner(self, owner_id: str) -> str:
        owner_block = _as_mapping(_as_mapping(self.config.get("owners")).get(owner_id))
        return str(
            owner_block.get("default_correspondent_policy")
            or owner_block.get("default_policy")
            or "correspondent"
        )

    def _policy_tools(self, policy_name: str, is_owner: bool) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
        if is_owner:
            return frozenset({"*"}), frozenset(), frozenset()

        policy = _as_mapping(_as_mapping(self.config.get("policies")).get(policy_name))
        tools = policy.get("tools")
        if isinstance(tools, Mapping):
            allow = _normalize_patterns(tools.get("allow"))
            deny = _normalize_patterns(tools.get("deny"))
            ask_owner = _normalize_patterns(tools.get("ask_owner"))
        else:
            allow = _normalize_patterns(tools)
            deny = frozenset()
            ask_owner = frozenset()

        # Fail closed when owner/correspondent policy is configured but a
        # non-owner policy is missing or malformed.
        return allow, deny, ask_owner

    def _mcp_visibility_configured(self) -> bool:
        if _as_mapping(self.config.get("mcp_policy")):
            return True
        for server_cfg in _as_mapping(self.config.get("mcp_servers")).values():
            if not isinstance(server_cfg, Mapping):
                continue
            if any(
                key in server_cfg
                for key in (
                    "access",
                    "credential_source",
                    "mcp_policy",
                    "policy",
                    "policy_profile",
                    "principal_overlays",
                    "requester_credentials",
                    "visibility",
                    "visible_to",
                )
            ):
                return True
        return False

    def resolve(
        self,
        source: Any,
        *,
        session_key: str = "",
    ) -> PermissionContext | None:
        if not self.is_configured():
            return None

        requester = self.principals.resolve(source)
        owner_ids = set(requester.owner_ids)
        principal_block = self._principal_block(requester)

        if owner_ids:
            subject_owner_id = sorted(owner_ids)[0]
            relationship = "owner"
            policy_name = "owner"
        elif principal_block:
            subject_owner_id = str(
                principal_block.get("subject_owner")
                or principal_block.get("owner")
                or self._single_owner_id()
                or ""
            )
            relationship = str(principal_block.get("relationship") or "correspondent")
            policy_name = str(principal_block.get("policy") or relationship)
        else:
            subject_owner_id = self._single_owner_id()
            relationship = self._default_policy_for_owner(subject_owner_id) if subject_owner_id else "blocked"
            policy_name = relationship

        if relationship == "blocked" or not subject_owner_id:
            allow = frozenset()
            deny = frozenset({"*"})
            ask_owner = frozenset()
        else:
            allow, deny, ask_owner = self._policy_tools(policy_name, relationship == "owner")

        policy = _as_mapping(_as_mapping(self.config.get("policies")).get(policy_name))
        ctx = PermissionContext(
            requester=requester,
            subject_owner_id=subject_owner_id,
            platform=platform_name(getattr(source, "platform", "")),
            scope=self._scope_for_source(source),
            session_key=session_key,
            relationship=relationship,
            policy_name=policy_name,
            tool_allow_patterns=allow,
            tool_deny_patterns=deny,
            tool_ask_owner_patterns=ask_owner,
            resource_rules=_as_mapping(policy.get("resources")),
            mcp_policy=_as_mapping(self.config.get("mcp_policy")),
            policy_active=True,
        )
        mcp_servers = _as_mapping(self.config.get("mcp_servers"))
        mcp_visibility_active = bool(mcp_servers) and self._mcp_visibility_configured()
        if mcp_visibility_active:
            projected_mcp_servers = ctx.filter_mcp_servers(mcp_servers)
            mcp_visible_tool_patterns = frozenset(
                f"mcp_{_sanitize_mcp_name_component(name)}_*"
                for name in projected_mcp_servers
            )
            projection_raw = json.dumps(projected_mcp_servers, sort_keys=True, default=str)
            ctx = replace(
                ctx,
                mcp_visible_tool_patterns=mcp_visible_tool_patterns,
                mcp_visibility_active=True,
                mcp_projection_signature=hashlib.sha256(projection_raw.encode("utf-8")).hexdigest()[:16],
            )
        return ctx

    def fail_closed_context(
        self,
        source: Any,
        *,
        session_key: str = "",
        policy_name: str = "policy_error",
    ) -> PermissionContext:
        """Return a deny-all context for configured-policy error paths."""

        try:
            requester = self.principals.resolve(source)
        except Exception:
            requester = Principal(key="unknown", display_name="unknown")
        subject_owner_id = (
            sorted(requester.owner_ids)[0]
            if requester.owner_ids
            else (self._single_owner_id() or "unresolved")
        )
        return PermissionContext(
            requester=requester,
            subject_owner_id=subject_owner_id,
            platform=platform_name(getattr(source, "platform", "")),
            scope=self._scope_for_source(source),
            session_key=session_key,
            relationship="blocked",
            policy_name=policy_name,
            tool_allow_patterns=frozenset(),
            tool_deny_patterns=frozenset({"*"}),
            tool_ask_owner_patterns=frozenset(),
            resource_rules={},
            mcp_policy=_as_mapping(self.config.get("mcp_policy")),
            mcp_visibility_active=bool(_as_mapping(self.config.get("mcp_servers"))),
            mcp_projection_signature="fail_closed",
            policy_active=True,
        )


def configured_policy_fingerprint(config: Mapping[str, Any] | None) -> str:
    cfg = config if isinstance(config, Mapping) else {}
    payload = {
        "owners": cfg.get("owners"),
        "principals": cfg.get("principals"),
        "policies": cfg.get("policies"),
        "mcp_policy": cfg.get("mcp_policy"),
        "mcp_servers": cfg.get("mcp_servers"),
    }
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "PermissionContext",
    "PermissionResolver",
    "ResourceRule",
    "ToolRule",
    "configured_policy_fingerprint",
    "get_current_permission_context",
    "normalize_principal_key",
    "reset_current_permission_context",
    "set_current_permission_context",
]
