"""Deterministic stop gate for assistant-to-assistant conversations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class BotConversationDecision:
    should_reply: bool
    reason: str
    normalized_text: str = ""


_THREAD_CONTEXT_RE = re.compile(
    r"^\s*\[Thread context[^\]]*\]\s*:?\s*.*?(?:\n\s*\n|$)",
    re.I | re.S,
)
_MENTION_RE = re.compile(r"<@[A-Z0-9]+>")
_SPACE_RE = re.compile(r"\s+")

_TERMINAL_PATTERNS = [
    re.compile(r"^\s*final\s*:", re.I),
    re.compile(r"\b(?:done|all set|no further action|no reply needed|stop here|we can stop|end of conversation)\b", re.I),
    re.compile(r"\b(?:thanks|thank you|got it|ok(?:ay)?|sounds good|understood|acknowledged)\b[.! ]*$", re.I),
    re.compile(r"\b(?:confirmed|scheduled|booked|calendar invite (?:sent|created)|meeting is set)\b", re.I),
]

_DIAGNOSTIC_PATTERNS = [
    re.compile(r"\bno home channel is set\b", re.I),
    re.compile(r"\btype\s+/(?:hermes\s+)?sethome\b", re.I),
    re.compile(r"\bmodel returned empty after tool calls\b", re.I),
    re.compile(r"\bnudging to continue\b", re.I),
    re.compile(r"\b(?:sorry,\s*)?i encountered an error\b", re.I),
    re.compile(r"\btry again or use\s+/reset\b", re.I),
    re.compile(r"\bframework error\b", re.I),
    re.compile(r"\btypeerror\b", re.I),
    re.compile(r"(?:^|\n)\s*:books:\s*(?:skill_view|skills_list|skill_manage)\s*:", re.I),
]

_SCHEDULING_PROGRESS_PATTERNS = [
    re.compile(r"\b(?:meeting|schedule|calendar|availability|available|free|busy|slot|time|timezone|duration)\b", re.I),
    re.compile(r"\b(?:propose|offer|prefer|works?|doesn't work|cannot do|can do|hold|invite|attendees?)\b", re.I),
    re.compile(r"\b(?:owner|assistant|approval|confirm|request|ask|check)\b", re.I),
]

_QUESTION_OR_REQUEST_PATTERNS = [
    re.compile(r"\?"),
    re.compile(r"\b(?:can you|could you|would you|please|which|what|when|does that work|do any of these)\b", re.I),
]


def normalize_bot_conversation_text(text: str) -> str:
    """Normalize bot-authored Slack text for loop detection."""

    cleaned = _THREAD_CONTEXT_RE.sub("", text or "")
    cleaned = _MENTION_RE.sub("", cleaned)
    cleaned = cleaned.strip().lower()
    return _SPACE_RE.sub(" ", cleaned)


def _matches_any(patterns: list[re.Pattern[str]], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def evaluate_bot_conversation_turn(
    text: str,
    *,
    state: Mapping[str, Any] | None = None,
    max_turns: int = 4,
) -> BotConversationDecision:
    """Decide whether an inbound bot message deserves another assistant reply.

    This is intentionally deterministic and conservative. It is meant to keep
    assistant-to-assistant scheduling useful while preventing ack/final-answer
    loops from consuming turns indefinitely.
    """

    normalized = normalize_bot_conversation_text(text)
    if not normalized:
        return BotConversationDecision(False, "empty", normalized)

    if _matches_any(_DIAGNOSTIC_PATTERNS, normalized):
        return BotConversationDecision(False, "diagnostic", normalized)

    current_turns = 0
    recent: tuple[str, ...] = ()
    if isinstance(state, Mapping):
        try:
            current_turns = int(state.get("turns") or 0)
        except (TypeError, ValueError):
            current_turns = 0
        raw_recent = state.get("recent_texts") or ()
        if isinstance(raw_recent, (list, tuple, set)):
            recent = tuple(str(item) for item in raw_recent)

    if max_turns > 0 and current_turns >= max_turns:
        return BotConversationDecision(False, "max_turns", normalized)

    if normalized in recent:
        return BotConversationDecision(False, "repeat", normalized)

    has_request = _matches_any(_QUESTION_OR_REQUEST_PATTERNS, normalized)
    has_progress = _matches_any(_SCHEDULING_PROGRESS_PATTERNS, normalized)
    terminal = _matches_any(_TERMINAL_PATTERNS, normalized)

    if terminal and not has_request:
        return BotConversationDecision(False, "terminal", normalized)

    # Short non-question bot acknowledgements are almost always loop fuel.
    if not has_request and not has_progress and len(normalized.split()) <= 12:
        return BotConversationDecision(False, "low_information", normalized)

    return BotConversationDecision(True, "continue", normalized)
