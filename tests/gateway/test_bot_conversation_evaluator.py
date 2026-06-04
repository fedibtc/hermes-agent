from gateway.bot_conversation_evaluator import evaluate_bot_conversation_turn


def test_allows_scheduling_question():
    decision = evaluate_bot_conversation_turn(
        "My owner is free Tuesday 10:00 or 14:00 UTC. Which slot works for your owner?",
        state={"turns": 1, "recent_texts": []},
    )

    assert decision.should_reply is True
    assert decision.reason == "continue"


def test_stops_terminal_acknowledgement():
    decision = evaluate_bot_conversation_turn(
        "Thanks, all set.",
        state={"turns": 1, "recent_texts": []},
    )

    assert decision.should_reply is False
    assert decision.reason == "terminal"


def test_stops_repeated_turn():
    text = "Does Tuesday at 10:00 UTC work?"
    first = evaluate_bot_conversation_turn(text, state={"turns": 1, "recent_texts": []})
    second = evaluate_bot_conversation_turn(
        text,
        state={"turns": 2, "recent_texts": [first.normalized_text]},
    )

    assert first.should_reply is True
    assert second.should_reply is False
    assert second.reason == "repeat"


def test_stops_after_max_turns():
    decision = evaluate_bot_conversation_turn(
        "Can you check whether Wednesday morning works for the owner?",
        state={"turns": 4, "recent_texts": []},
        max_turns=4,
    )

    assert decision.should_reply is False
    assert decision.reason == "max_turns"


def test_stops_short_low_information_message():
    decision = evaluate_bot_conversation_turn(
        "Okay.",
        state={"turns": 0, "recent_texts": []},
    )

    assert decision.should_reply is False
    assert decision.reason in {"terminal", "low_information"}


def test_stops_final_scheduling_message():
    decision = evaluate_bot_conversation_turn(
        "FINAL: Proposed meeting slot is 2026-06-04 16:00 UTC.",
        state={"turns": 1, "recent_texts": []},
    )

    assert decision.should_reply is False
    assert decision.reason == "terminal"


def test_stops_platform_diagnostic_messages():
    for text in (
        "No home channel is set for Slack. Type /hermes sethome to make this chat your home channel.",
        ':books: skill_view: "google-workspace"',
        "Model returned empty after tool calls - nudging to continue",
        "Sorry, I encountered an error (TypeError). Try again or use /reset.",
    ):
        decision = evaluate_bot_conversation_turn(
            text,
            state={"turns": 1, "recent_texts": []},
        )

        assert decision.should_reply is False
        assert decision.reason == "diagnostic"
