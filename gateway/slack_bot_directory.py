"""Persistent directory of Slack bot peers and their owner identity claims."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from hermes_cli.config import get_hermes_home
from utils import atomic_json_write


DIRECTORY_PATH = get_hermes_home() / "slack_bot_agents.json"

_SLACK_MENTION_RE = re.compile(r"<@([UW][A-Z0-9]+)>")
_SPACE_RE = re.compile(r"\s+")
_GENERIC_OWNER_LABELS = {
    "my owner",
    "the owner",
    "owner",
    "my user",
    "the user",
    "user",
    "their owner",
    "your owner",
}

_INTRO_OWNER_PATTERNS = [
    re.compile(
        r"\bI\s+am\s+(?:@\w+|[\w ._-]+)?\s*,?\s*(?:an?\s+)?(?:Hermes\s+)?"
        r"(?:assistant|agent|bot)\s+(?:for|to|of)\s+(?P<owner>[^.\n;,]+)",
        re.I,
    ),
    re.compile(
        r"\b(?:my|the)\s+owner\s+(?:is|=)\s+(?P<owner>[^.\n;,]+)",
        re.I,
    ),
    re.compile(
        r"\bI\s+(?:represent|assist)\s+(?P<owner>[^.\n;,]+)",
        re.I,
    ),
]


def _now() -> float:
    return time.time()


def _clean_label(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"^['\"`]+|['\"`]+$", "", text)
    text = _SPACE_RE.sub(" ", text)
    return text[:120]


def _usable_owner_label(value: Any) -> str:
    label = _clean_label(value)
    label = re.sub(
        r"^(?:please\s+)?(?:coordinate\s+with|ask|contact|message|talk\s+to)\s+",
        "",
        label,
        flags=re.I,
    ).strip()
    if not label:
        return ""
    if label.lower() in _GENERIC_OWNER_LABELS:
        return ""
    return label


def _load() -> dict[str, Any]:
    if not DIRECTORY_PATH.exists():
        return {"version": 1, "agents": {}}
    try:
        data = json.loads(DIRECTORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "agents": {}}
    if not isinstance(data, dict):
        return {"version": 1, "agents": {}}
    agents = data.get("agents")
    if not isinstance(agents, dict):
        data["agents"] = {}
    data.setdefault("version", 1)
    return data


def _save(data: Mapping[str, Any]) -> None:
    atomic_json_write(DIRECTORY_PATH, dict(data), sort_keys=True)


def _record_key(team_id: str, user_id: str) -> str:
    team = str(team_id or "_").strip() or "_"
    user = str(user_id or "").strip()
    return f"{team}:{user}"


def extract_slack_mentions(text: str) -> list[str]:
    """Return Slack user IDs mentioned in *text* in first-seen order."""

    seen: set[str] = set()
    mentions: list[str] = []
    for match in _SLACK_MENTION_RE.finditer(text or ""):
        user_id = match.group(1)
        if user_id not in seen:
            seen.add(user_id)
            mentions.append(user_id)
    return mentions


def extract_owner_label_from_text(text: str) -> str:
    """Best-effort parse of a bot introduction owner label."""

    for pattern in _INTRO_OWNER_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return _usable_owner_label(match.group("owner"))
    return ""


def extract_owner_label_near_mention(text: str, user_id: str) -> str:
    """Best-effort parse of an owner label near a Slack bot mention."""

    mention = f"<@{user_id}>"
    haystack = text or ""
    idx = haystack.find(mention)
    if idx < 0:
        return ""

    start = max(0, idx - 120)
    end = min(len(haystack), idx + len(mention) + 120)
    window = haystack[start:end].replace(mention, "MENTION")

    patterns = [
        re.compile(r"(?P<owner>[A-Za-z][A-Za-z0-9 ._-]{1,80})'s\s+(?:bot|assistant|agent)\s+MENTION", re.I),
        re.compile(r"(?P<owner>[A-Za-z][A-Za-z0-9 ._-]{1,80})'s\s+MENTION", re.I),
        re.compile(r"MENTION\s+(?:is|as)?\s*(?:the\s+)?(?:bot|assistant|agent)\s+(?:for|of|to)\s+(?P<owner>[^.\n;,]+)", re.I),
        re.compile(r"(?:bot|assistant|agent)\s+(?:for|of|to)\s+(?P<owner>[A-Za-z][A-Za-z0-9 ._-]{1,80})\s+MENTION", re.I),
    ]
    for pattern in patterns:
        match = pattern.search(window)
        if match:
            return _usable_owner_label(match.group("owner"))
    return ""


def upsert_slack_bot_agent(
    *,
    team_id: str = "",
    user_id: str,
    bot_id: str = "",
    name: str = "",
    display_name: str = "",
    real_name: str = "",
    owner_label: str = "",
    dm_channel_id: str = "",
    deleted: bool | None = None,
    sources: Iterable[str] = (),
) -> dict[str, Any]:
    """Create or update one known Slack bot peer record."""

    user_id = str(user_id or "").strip()
    if not user_id:
        return {}

    data = _load()
    agents: dict[str, Any] = data.setdefault("agents", {})
    key = _record_key(team_id, user_id)
    now = _now()
    record = dict(agents.get(key) or {})
    record.setdefault("first_seen", now)
    record["last_seen"] = now
    record["team_id"] = str(team_id or "")
    record["user_id"] = user_id

    for field, value in (
        ("bot_id", bot_id),
        ("name", name),
        ("display_name", display_name),
        ("real_name", real_name),
        ("dm_channel_id", dm_channel_id),
    ):
        cleaned = _clean_label(value)
        if cleaned:
            record[field] = cleaned

    owner = _usable_owner_label(owner_label)
    if owner:
        record["owner_label"] = owner
        record["owner_claimed_at"] = now

    if deleted is not None:
        record["deleted"] = bool(deleted)

    existing_sources = set(record.get("sources") or [])
    existing_sources.update(str(source) for source in sources if str(source).strip())
    record["sources"] = sorted(existing_sources)

    aliases = {
        str(record.get("user_id") or ""),
        str(record.get("bot_id") or ""),
        str(record.get("name") or ""),
        str(record.get("display_name") or ""),
        str(record.get("real_name") or ""),
    }
    record["aliases"] = sorted(alias for alias in aliases if alias)

    agents[key] = record
    data["updated_at"] = now
    _save(data)
    return record


def upsert_from_slack_user(
    user: Mapping[str, Any],
    *,
    team_id: str = "",
    owner_label: str = "",
    dm_channel_id: str = "",
    source: str = "users.list",
) -> dict[str, Any]:
    """Persist a Slack ``user`` object if it represents a bot user."""

    if not isinstance(user, Mapping):
        return {}
    profile = user.get("profile") if isinstance(user.get("profile"), Mapping) else {}
    if not (user.get("is_bot") or profile.get("bot_id")):
        return {}
    return upsert_slack_bot_agent(
        team_id=team_id,
        user_id=str(user.get("id") or ""),
        bot_id=str(profile.get("bot_id") or ""),
        name=str(user.get("name") or ""),
        display_name=str(profile.get("display_name") or ""),
        real_name=str(profile.get("real_name") or user.get("real_name") or ""),
        owner_label=owner_label,
        dm_channel_id=dm_channel_id,
        deleted=bool(user.get("deleted", False)),
        sources=[source],
    )


def known_slack_bot_agents(
    *,
    team_id: str = "",
    include_deleted: bool = False,
    exclude_user_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Return known Slack bot peers from the persistent directory."""

    excluded = {str(value) for value in exclude_user_ids}
    records = []
    for record in (_load().get("agents") or {}).values():
        if not isinstance(record, Mapping):
            continue
        if team_id and record.get("team_id") not in {"", team_id}:
            continue
        if not include_deleted and record.get("deleted"):
            continue
        if record.get("user_id") in excluded:
            continue
        records.append(dict(record))
    return sorted(records, key=lambda item: (str(item.get("name") or ""), str(item.get("user_id") or "")))


def self_owner_label_from_config(config_path: Path | None = None) -> str:
    """Return a concise owner label for this Hermes instance."""

    if config_path is None:
        config_path = get_hermes_home() / "config.yaml"
    try:
        import yaml

        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return "configured owner"

    owners = data.get("owners")
    if not isinstance(owners, Mapping) or not owners:
        return "configured owner"

    owner_id, block = next(iter(owners.items()))
    if isinstance(block, Mapping):
        label = (
            block.get("name")
            or block.get("display_name")
            or block.get("label")
            or block.get("description")
        )
        if label:
            return _clean_label(label)
        principals = block.get("principals")
        if isinstance(principals, str):
            principal_preview = principals
        elif isinstance(principals, Iterable):
            principal_preview = ", ".join(str(item) for item in list(principals)[:2])
        else:
            principal_preview = ""
        if principal_preview:
            return f"{owner_id} ({principal_preview})"
    return str(owner_id)
