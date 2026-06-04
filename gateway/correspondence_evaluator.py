"""Deterministic correspondence safety evaluator.

This is a conservative first layer for owner/correspondent deployments. It
does not try to infer subtle intent; it catches obvious privacy and authority
violations before a response is delivered to a non-owner.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class CorrespondenceEvaluation:
    decision: str
    risk: str
    violations: tuple[str, ...] = ()
    safe_response: str = ""
    owner_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SECRET_LITERAL_PATTERNS = [
    re.compile(r"\b(?:api[_ -]?key|secret|password|credential|auth[_ -]?token)\s*[:=]\s*\S{6,}", re.I),
    re.compile(r"\b(?:authorization:\s*bearer|bearer\s+[A-Za-z0-9._~+/=-]{12,})", re.I),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})\b"),
]

_SECRET_REFERENCE_PATTERNS = [
    re.compile(r"\b(?:api[_ -]?key|secret|password|credential|auth[_ -]?token|access[_ -]?token)\b", re.I),
]

_PRIVATE_LABEL_PATTERNS = [
    re.compile(r"\bowner[-_ ]private\b", re.I),
    re.compile(r"\bprivate calendar\b", re.I),
    re.compile(r"\bprivate (?:file|memory|note|meeting|event|calendar|repo|repository|channel)\b", re.I),
    re.compile(r"\b(?:calendar|event)\s+(?:title|description|location|attendees?)\b", re.I),
    re.compile(r"\bconfidential (?:doc|document|memo|file|note|meeting)\b", re.I),
]

_AUTHORITY_PATTERNS = [
    re.compile(r"\bI (?:approve|authorize|commit|promise|agree|accept)\b", re.I),
    re.compile(r"\bon behalf of (?:the owner|[A-Z][A-Za-z]+)\b", re.I),
    re.compile(r"\b(?:the owner|[A-Z][A-Za-z]+) (?:thinks|believes|wants|intends|agrees|approved|authorized)\b", re.I),
]

_OWNER_CLAIM_PATTERNS = [
    re.compile(r"\b(?:the owner|[A-Z][A-Za-z]+) (?:said|told me|confirmed|decided|asked me to|wants|intends|believes|thinks)\b", re.I),
]

_LEGAL_FINANCIAL_AUTHORITY_PATTERNS = [
    re.compile(r"\b(?:approve|authorize|accept|agree to|sign|commit to) (?:the )?(?:contract|terms|agreement|payment|refund|invoice|discount|offer)\b", re.I),
    re.compile(r"\b(?:we|I) will (?:pay|refund|hire|fire|promote|sign|accept|approve)\b", re.I),
    re.compile(r"\b(?:legal|financial|HR|employment) (?:approval|commitment|decision|promise)\b", re.I),
]

_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\b(?:ignored|bypassed|overrode|disabled) (?:the )?(?:owner|gateway|system|developer|policy|instructions?)\b", re.I),
    re.compile(r"\b(?:hidden|system|developer) instructions? (?:say|said|told me|override)\b", re.I),
    re.compile(r"\b(?:jailbreak|prompt injection|ignore previous instructions)\b", re.I),
]

_SOCIAL_ENGINEERING_PATTERNS = [
    re.compile(r"\b(?:internal|private|hidden) (?:link|url|doc|document|repo|repository|channel|mcp output)\b", re.I),
    re.compile(r"\braw (?:owner )?mcp output\b", re.I),
    re.compile(r"\b(?:owner|private) mcp (?:server|tool|result|output)\b", re.I),
]

_REFUSAL_PATTERNS = [
    re.compile(r"\b(?:I )?(?:can't|cannot|won't|will not|am unable to|not able to|can't safely)\b", re.I),
    re.compile(r"\b(?:decline|refuse|not allowed|requires owner approval|without owner approval)\b", re.I),
]

_SIDE_EFFECT_TOOL_NAMES = {
    "send_message",
    "calendar_hold",
    "calendar_commit",
    "write_file",
    "patch",
    "terminal",
    "execute_code",
}


def _tool_names_from_messages(messages: Iterable[Mapping[str, Any]] | None) -> tuple[str, ...]:
    names: list[str] = []
    for message in messages or []:
        if not isinstance(message, Mapping):
            continue
        if message.get("role") == "tool" and message.get("name"):
            names.append(str(message["name"]))
        for call in message.get("tool_calls") or []:
            if isinstance(call, Mapping):
                fn = call.get("function")
                if isinstance(fn, Mapping) and fn.get("name"):
                    names.append(str(fn["name"]))
    return tuple(names)


def _is_safe_refusal(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in _REFUSAL_PATTERNS)


def _tool_decision(permission_context: Any, tool_name: str) -> str:
    """Return the policy decision for ``tool_name`` ("allow"/"deny"/"ask_owner").

    Falls back to ``"deny"`` when no decision can be determined, so an
    indeterminate context stays on the conservative (flag-as-violation) side.
    """
    if permission_context is None or not hasattr(permission_context, "tool_decision"):
        return "deny"
    try:
        return str(permission_context.tool_decision(tool_name) or "deny")
    except Exception:
        return "deny"


class CorrespondenceEvaluator:
    """Evaluate outbound text for non-owner recipient safety."""

    def _audit(
        self,
        permission_context: Any,
        evaluation: CorrespondenceEvaluation,
    ) -> None:
        try:
            from gateway.owner_audit import append_audit_event_for_context

            append_audit_event_for_context(
                permission_context,
                "correspondence_evaluated",
                details={
                    "decision": evaluation.decision,
                    "risk": evaluation.risk,
                    "violations": evaluation.violations,
                },
            )
        except Exception:
            pass

    def evaluate(
        self,
        response: str,
        *,
        permission_context: Any = None,
        messages: Iterable[Mapping[str, Any]] | None = None,
    ) -> CorrespondenceEvaluation:
        if permission_context is None or bool(getattr(permission_context, "is_owner", False)):
            return CorrespondenceEvaluation(decision="allow", risk="low")

        text = response or ""
        safe_refusal = _is_safe_refusal(text)
        violations: list[str] = []
        if any(pattern.search(text) for pattern in _SECRET_LITERAL_PATTERNS):
            violations.append("privacy")
        if not safe_refusal and any(pattern.search(text) for pattern in _SECRET_REFERENCE_PATTERNS):
            violations.append("privacy")
        if not safe_refusal and any(pattern.search(text) for pattern in _PRIVATE_LABEL_PATTERNS):
            violations.append("privacy")
        if not safe_refusal and any(pattern.search(text) for pattern in _SOCIAL_ENGINEERING_PATTERNS):
            violations.extend(["privacy", "social_engineering"])
        if not safe_refusal and any(pattern.search(text) for pattern in _PROMPT_INJECTION_PATTERNS):
            violations.append("prompt_injection")
        if not safe_refusal and any(pattern.search(text) for pattern in _AUTHORITY_PATTERNS):
            violations.append("authority")
        if not safe_refusal and any(pattern.search(text) for pattern in _OWNER_CLAIM_PATTERNS):
            violations.extend(["authority", "unsupported_claim"])
        if not safe_refusal and any(pattern.search(text) for pattern in _LEGAL_FINANCIAL_AUTHORITY_PATTERNS):
            violations.extend(["authority", "legal_financial"])

        # Side-effect tools are only an authority violation when the requester's
        # policy did NOT sanction them. A correspondent whose policy explicitly
        # allows e.g. send_message is running a *delegated* workflow, so the
        # successful "I sent it" reply must not be replaced by a refusal.
        # ask_owner tools don't perform the action either — the executor turns
        # them into a durable approval request — so they are not overreach.
        tool_names = _tool_names_from_messages(messages)
        unauthorized_side_effects = [
            name
            for name in tool_names
            if name in _SIDE_EFFECT_TOOL_NAMES
            and _tool_decision(permission_context, name) not in ("allow", "ask_owner")
        ]
        if unauthorized_side_effects:
            violations.append("authority")

        if not violations:
            result = CorrespondenceEvaluation(decision="allow", risk="low")
            self._audit(permission_context, result)
            return result

        unique = tuple(sorted(set(violations)))
        if "privacy" in unique:
            safe = (
                "I can't share owner-private details or credentials. I can help "
                "with a safe summary, availability-only scheduling, or an owner "
                "approval request."
            )
            risk = "high"
        elif "legal_financial" in unique:
            safe = (
                "I can't make legal, financial, or employment commitments for "
                "the owner without owner approval. I can draft the request or "
                "ask the owner to review it."
            )
            risk = "high"
        elif "prompt_injection" in unique or "social_engineering" in unique:
            safe = (
                "I can't ignore owner policy or share private access details. "
                "I can help with a policy-safe request or ask the owner to review it."
            )
            risk = "high"
        else:
            safe = (
                "I can't make commitments or speak for the owner without owner "
                "approval. I can draft the request or ask the owner to approve it."
            )
            risk = "medium"
        result = CorrespondenceEvaluation(
            decision="ask_owner",
            risk=risk,
            violations=unique,
            safe_response=safe,
            owner_summary="Outbound response was replaced by the correspondence evaluator.",
        )
        self._audit(permission_context, result)
        return result


def evaluate_correspondence(
    response: str,
    *,
    permission_context: Any = None,
    messages: Iterable[Mapping[str, Any]] | None = None,
) -> CorrespondenceEvaluation:
    return CorrespondenceEvaluator().evaluate(
        response,
        permission_context=permission_context,
        messages=messages,
    )
