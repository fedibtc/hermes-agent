"""Policy-aware owner digital-twin context assembly."""

from __future__ import annotations

from typing import Any, Mapping


_VALID_RESPONSE_MODES = {"answer_as_assistant", "draft_for_owner", "respond_on_behalf"}


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _clean_text(value: Any, *, max_chars: int = 1800) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _first_text(mapping: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        text = _clean_text(mapping.get(key))
        if text:
            return text
    return ""


def _first_mapping(*values: Any) -> Mapping[str, Any]:
    for value in values:
        mapped = _as_mapping(value)
        if mapped:
            return mapped
    return {}


def _as_text_list(value: Any, *, max_items: int = 3, max_chars: int = 360) -> list[str]:
    if value is None:
        return []
    raw_items = value if isinstance(value, list | tuple) else [value]
    items: list[str] = []
    for item in raw_items:
        if isinstance(item, Mapping):
            text = _first_text(item, "text", "content", "message", "example", "excerpt")
        else:
            text = _clean_text(item, max_chars=max_chars)
        if text:
            items.append(text)
        if len(items) >= max_items:
            break
    return items


def _response_mode(twin_policy: Mapping[str, Any], *, is_owner: bool) -> str:
    raw_mode = str(twin_policy.get("response_mode") or "answer_as_assistant").strip().lower()
    mode = raw_mode if raw_mode in _VALID_RESPONSE_MODES else "answer_as_assistant"
    if not is_owner and mode == "respond_on_behalf" and not twin_policy.get("allow_respond_on_behalf"):
        return "draft_for_owner"
    return mode


def _mode_directive(mode: str, *, is_owner: bool) -> str:
    if is_owner:
        return "Owner session: answer directly and preserve full owner control."
    if mode == "draft_for_owner":
        return (
            "Draft-for-owner mode: write proposed wording for owner review; do not claim "
            "the owner has approved it and do not send it unless an owner-approved tool result says so."
        )
    if mode == "respond_on_behalf":
        return (
            "Respond-on-behalf mode: answer in an owner-like style only for delegated low-risk topics; "
            "escalate commitments, private facts, uncertainty, or third-party sends to owner approval."
        )
    return (
        "Assistant mode: answer as Hermes, the owner's assistant; do not impersonate the owner "
        "or state unsupported owner intent."
    )


def _style_confidence_text(*sources: Mapping[str, Any]) -> str:
    for source in sources:
        value = source.get("style_confidence")
        if value is None:
            value = source.get("confidence")
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _owner_honcho_block(
    config: Mapping[str, Any],
    owner: Mapping[str, Any],
    owner_id: str,
) -> Mapping[str, Any]:
    root_honcho = _as_mapping(config.get("honcho"))
    root_twin = _as_mapping(config.get("digital_twin"))
    return _first_mapping(
        owner.get("honcho_twin"),
        _as_mapping(owner.get("digital_twin")).get("honcho"),
        _as_mapping(owner.get("honcho")).get("digital_twin"),
        _as_mapping(_as_mapping(root_honcho.get("digital_twin")).get("owners")).get(owner_id),
        _as_mapping(root_honcho.get("owners")).get(owner_id),
        _as_mapping(_as_mapping(root_twin.get("honcho")).get("owners")).get(owner_id),
    )


def _policy_block(config: Mapping[str, Any], policy_name: str) -> Mapping[str, Any]:
    return _as_mapping(_as_mapping(config.get("policies")).get(policy_name))


class OwnerTwinContextAssembler:
    """Compose owner identity/style context without bypassing policy."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config if isinstance(config, Mapping) else {}

    def assemble(self, permission_context: Any) -> str:
        if permission_context is None:
            return ""
        owner_id = str(getattr(permission_context, "subject_owner_id", "") or "")
        if not owner_id:
            return ""
        owner = _as_mapping(_as_mapping(self.config.get("owners")).get(owner_id))
        if not owner:
            return ""

        policy = _policy_block(self.config, str(getattr(permission_context, "policy_name", "") or ""))
        twin_policy = _as_mapping(policy.get("digital_twin"))
        is_owner = bool(getattr(permission_context, "is_owner", False))

        response_mode = str(
            _response_mode(twin_policy, is_owner=is_owner)
        )

        honcho = _owner_honcho_block(self.config, owner, owner_id)

        sections = [
            "[Owner twin context]",
            f"- Subject owner: {owner_id}",
            f"- Response mode: {response_mode}",
            f"- Mode directive: {_mode_directive(response_mode, is_owner=is_owner)}",
        ]

        used_honcho = False
        if is_owner:
            assistant_identity = _first_text(
                honcho,
                "assistant_identity",
                "private_assistant_identity",
                "ai_identity",
                "ai_profile",
                "ai_representation",
            )
            used_honcho = used_honcho or bool(assistant_identity)
            assistant_identity = assistant_identity or _first_text(
                owner,
                "assistant_identity",
                "private_assistant_identity",
                "soul",
            )
            profile = _first_text(
                honcho,
                "private_profile",
                "owner_profile",
                "profile",
                "representation",
                "user_representation",
                "card",
            )
            used_honcho = used_honcho or bool(profile)
            profile = profile or _first_text(owner, "profile", "private_profile")
            style = _first_text(
                honcho,
                "communication_style",
                "private_style",
                "owner_style",
                "style",
            )
            used_honcho = used_honcho or bool(style)
            style = style or _first_text(owner, "style", "communication_style")
            style_exemplars = _as_text_list(
                honcho.get("approved_style_exemplars")
                or honcho.get("style_exemplars")
                or owner.get("approved_style_exemplars")
                or owner.get("style_exemplars")
            )
        else:
            assistant_identity = _first_text(
                honcho,
                "public_assistant_identity",
                "assistant_identity_public",
            )
            used_honcho = used_honcho or bool(assistant_identity)
            assistant_identity = assistant_identity or _first_text(owner, "public_assistant_identity", "assistant_identity_public")
            profile = _first_text(
                honcho,
                "public_profile",
                "public_owner_profile",
                "public_representation",
            )
            used_honcho = used_honcho or bool(profile)
            profile = profile or _first_text(owner, "public_profile")
            style = _first_text(
                honcho,
                "public_style",
                "style_public",
                "public_communication_style",
            )
            used_honcho = used_honcho or bool(style)
            style = style or _first_text(owner, "public_style", "style_public")
            style_exemplars = _as_text_list(
                honcho.get("public_style_exemplars")
                or honcho.get("approved_public_style_exemplars")
                or owner.get("public_style_exemplars")
                or owner.get("approved_public_style_exemplars")
                or twin_policy.get("public_style_exemplars")
            )

        if assistant_identity:
            sections.append(f"- Assistant identity: {assistant_identity}")
        if profile:
            sections.append(f"- Owner profile: {profile}")
        if style:
            sections.append(f"- Communication style: {style}")
        style_confidence = _style_confidence_text(twin_policy, honcho, owner)
        if style_confidence:
            sections.append(f"- Style confidence: {style_confidence}")
        if style_exemplars:
            sections.append("- Approved style exemplars:")
            for exemplar in style_exemplars:
                sections.append(f"  - {exemplar}")
        if used_honcho:
            sections.append("- Preferred memory source: Honcho")

        if not is_owner:
            relationship = str(getattr(permission_context, "relationship", "") or "correspondent")
            sections.append(f"- Requester relationship: {relationship}")
            sections.append(
                "- Do not disclose owner-private facts, intent, files, memory, calendar details, or credentials unless a policy-approved tool result explicitly provides them."
            )

        return "\n".join(sections)


def assemble_owner_twin_context(
    config: Mapping[str, Any] | None,
    permission_context: Any,
) -> str:
    return OwnerTwinContextAssembler(config).assemble(permission_context)
