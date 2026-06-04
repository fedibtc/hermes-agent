"""Tests for configurable conversation-mode policy resolution."""

from gateway.config import Platform
from gateway.conversation_policy import (
    infer_communication_mode,
    resolve_conversation_policy,
)
from gateway.session import SessionSource


def test_infer_communication_mode():
    assert infer_communication_mode(
        SessionSource(platform=Platform.SLACK, chat_id="D1", chat_type="dm", is_bot=True)
    ) == "bot_to_bot_dm"
    assert infer_communication_mode(
        SessionSource(platform=Platform.SLACK, chat_id="D2", chat_type="dm")
    ) == "human_to_bot_dm"
    assert infer_communication_mode(
        SessionSource(platform=Platform.SLACK, chat_id="C1", chat_type="group", is_bot=True)
    ) == "bot_in_shared_chat"
    assert infer_communication_mode(
        SessionSource(platform=Platform.TELEGRAM, chat_id="G1", chat_type="group")
    ) == "human_in_shared_chat"


def test_resolve_conversation_policy_defaults_to_prompt_and_suppression_for_bot_dm():
    policy = resolve_conversation_policy(
        SessionSource(
            platform=Platform.SLACK,
            chat_id="D100",
            chat_type="dm",
            is_bot=True,
        )
    )
    assert policy.communication_mode == "bot_to_bot_dm"
    assert policy.include_mode_prompt is True
    assert policy.suppress_tool_progress is True
    assert policy.suppress_interim_messages is True


def test_resolve_conversation_policy_allows_platform_overrides():
    policy = resolve_conversation_policy(
        SessionSource(
            platform=Platform.SLACK,
            chat_id="D100",
            chat_type="dm",
            is_bot=True,
        ),
        user_config={
            "display": {
                "bot_dm_suppress_tool_progress": False,
                "bot_dm_suppress_interim_messages": False,
            }
        },
        platform_key="slack",
    )
    assert policy.suppress_tool_progress is False
    assert policy.suppress_interim_messages is False


def test_conversation_policy_can_be_disabled(monkeypatch):
    monkeypatch.setenv("HERMES_CONVERSATION_POLICY", "0")
    policy = resolve_conversation_policy(
        SessionSource(
            platform=Platform.SLACK,
            chat_id="D100",
            chat_type="dm",
            is_bot=True,
        )
    )
    assert policy.include_mode_prompt is False
    assert policy.suppress_tool_progress is False
    assert policy.suppress_interim_messages is False
