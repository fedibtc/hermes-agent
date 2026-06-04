"""Principal identity helpers for multi-user gateway policy.

The gateway already carries platform-specific sender identifiers in
``SessionSource``.  This module normalizes those values into stable principal
keys so policy code can reason about "who is asking" without knowing whether
the message came from Telegram, Slack, email, or another adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


PrincipalKey = str


@dataclass(frozen=True)
class Principal:
    """A canonical requester identity resolved from a gateway source."""

    key: PrincipalKey
    display_name: str = ""
    kind: str = "human"
    owner_ids: frozenset[str] = field(default_factory=frozenset)
    aliases: frozenset[PrincipalKey] = field(default_factory=frozenset)


def platform_name(platform: Any) -> str:
    """Return a lower-case platform name from an enum or string-like value."""

    value = getattr(platform, "value", platform)
    return str(value or "").strip().lower()


def normalize_principal_key(value: Any) -> PrincipalKey:
    """Normalize a configured principal key.

    Keys are intentionally simple strings such as ``telegram:12345`` or
    ``email:alice@example.com``.  Empty and malformed values normalize to an
    empty string so callers can drop them.
    """

    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if ":" not in text:
        return text
    platform, rest = text.split(":", 1)
    platform = platform.strip().lower()
    rest = rest.strip()
    if not platform or not rest:
        return ""
    return f"{platform}:{rest}"


def principal_key_for(platform: Any, user_id: Any) -> PrincipalKey:
    """Build ``<platform>:<id>`` for a platform sender id."""

    plat = platform_name(platform)
    if not plat or user_id is None:
        return ""
    ident = str(user_id).strip()
    if not ident:
        return ""
    return f"{plat}:{ident}"


def _coerce_key_list(raw: Any) -> frozenset[PrincipalKey]:
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        values: Iterable[Any] = [raw]
    elif isinstance(raw, Iterable):
        values = raw
    else:
        values = [raw]
    return frozenset(
        key for key in (normalize_principal_key(v) for v in values) if key
    )


class PrincipalResolver:
    """Resolve ``SessionSource`` values into stable requester principals."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config if isinstance(config, Mapping) else {}

    def aliases_for_source(self, source: Any) -> frozenset[PrincipalKey]:
        """Return all useful principal aliases for a source."""

        if source is None:
            return frozenset()
        aliases: list[PrincipalKey] = []
        for attr in ("user_id_alt", "user_id"):
            key = principal_key_for(getattr(source, "platform", ""), getattr(source, attr, None))
            if key and key not in aliases:
                aliases.append(key)
        if not aliases:
            chat_id = getattr(source, "chat_id", None)
            chat_key = principal_key_for(getattr(source, "platform", ""), f"chat:{chat_id}" if chat_id else None)
            if chat_key:
                aliases.append(chat_key)
        return frozenset(aliases)

    def _configured_identity_for_key(
        self,
        key: PrincipalKey,
    ) -> tuple[PrincipalKey, frozenset[PrincipalKey]]:
        principals = self.config.get("principals")
        if not isinstance(principals, Mapping):
            return key, frozenset()

        normalized_key = normalize_principal_key(key)
        for configured_key, block in principals.items():
            canonical_key = normalize_principal_key(configured_key)
            if not canonical_key or not isinstance(block, Mapping):
                continue
            aliases = set(_coerce_key_list(block.get("aliases")))
            aliases.add(canonical_key)
            if normalized_key == canonical_key or normalized_key in aliases:
                return canonical_key, frozenset(aliases)
        return key, frozenset()

    def _owner_ids_for_aliases(self, aliases: frozenset[PrincipalKey]) -> frozenset[str]:
        owners = self.config.get("owners")
        if not isinstance(owners, Mapping) or not aliases:
            return frozenset()
        owner_ids: set[str] = set()
        for owner_id, owner_block in owners.items():
            if not isinstance(owner_block, Mapping):
                continue
            owner_keys = _coerce_key_list(owner_block.get("principals"))
            if aliases & owner_keys:
                owner_ids.add(str(owner_id))
        return frozenset(owner_ids)

    def resolve(self, source: Any) -> Principal:
        aliases = set(self.aliases_for_source(source))
        key = sorted(aliases)[0] if aliases else "unknown"
        key, configured_aliases = self._configured_identity_for_key(key)
        aliases.update(configured_aliases)
        owner_ids = self._owner_ids_for_aliases(frozenset(aliases))
        kind = "bot" if bool(getattr(source, "is_bot", False)) else "human"
        return Principal(
            key=key,
            display_name=str(getattr(source, "user_name", "") or key),
            kind=kind,
            owner_ids=owner_ids,
            aliases=frozenset(aliases or {key}),
        )


__all__ = [
    "Principal",
    "PrincipalKey",
    "PrincipalResolver",
    "normalize_principal_key",
    "principal_key_for",
    "platform_name",
]
