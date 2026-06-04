from gateway import slack_bot_directory as directory


def test_extracts_slack_mentions_in_order_without_duplicates():
    assert directory.extract_slack_mentions("Ask <@U123> and <@U456>, then <@U123>.") == [
        "U123",
        "U456",
    ]


def test_extracts_owner_label_from_bot_introduction():
    assert (
        directory.extract_owner_label_from_text(
            "I am fedstr, assistant for Alice Example. Can your owner meet?"
        )
        == "Alice Example"
    )


def test_ignores_generic_owner_label_from_bot_introduction():
    assert (
        directory.extract_owner_label_from_text(
            "I am fedstr, assistant for my owner. Can your owner meet?"
        )
        == ""
    )


def test_extracts_owner_label_near_bot_mention():
    assert (
        directory.extract_owner_label_near_mention(
            "Please coordinate with Alice Example's bot <@U123> for scheduling.",
            "U123",
        )
        == "Alice Example"
    )


def test_upsert_persists_bot_record(tmp_path, monkeypatch):
    monkeypatch.setattr(directory, "DIRECTORY_PATH", tmp_path / "slack_bot_agents.json")

    record = directory.upsert_slack_bot_agent(
        team_id="T1",
        user_id="U1",
        bot_id="B1",
        name="peerbot",
        owner_label="Alice",
        sources=["test"],
    )

    assert record["user_id"] == "U1"
    assert record["bot_id"] == "B1"
    assert record["owner_label"] == "Alice"
    assert directory.known_slack_bot_agents(team_id="T1")[0]["name"] == "peerbot"
