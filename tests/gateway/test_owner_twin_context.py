from types import SimpleNamespace

from gateway.owner_twin_context import assemble_owner_twin_context
from gateway.permissions import PermissionResolver


CONFIG = {
    "owners": {
        "owner": {
            "principals": ["telegram:owner"],
            "default_correspondent_policy": "coworker",
            "private_profile": "Private owner preference",
            "public_profile": "Public owner role",
            "communication_style": "Private direct style",
            "public_style": "Concise and direct",
        }
    },
    "principals": {
        "telegram:employee": {
            "relationship": "coworker",
            "subject_owner": "owner",
        }
    },
    "policies": {
        "coworker": {
            "tools": {"allow": ["clarify"]},
            "digital_twin": {"response_mode": "respond_on_behalf"},
        }
    },
}


def _source(user_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        platform="telegram",
        user_id=user_id,
        user_id_alt=None,
        user_name=user_id,
        chat_type="dm",
    )


def test_owner_gets_private_profile_and_style_context():
    ctx = PermissionResolver(CONFIG).resolve(_source("owner"), session_key="s")

    prompt = assemble_owner_twin_context(CONFIG, ctx)

    assert "Private owner preference" in prompt
    assert "Private direct style" in prompt
    assert "Public owner role" not in prompt


def test_correspondent_gets_public_context_and_conservative_mode():
    ctx = PermissionResolver(CONFIG).resolve(_source("employee"), session_key="s")

    prompt = assemble_owner_twin_context(CONFIG, ctx)

    assert "Public owner role" in prompt
    assert "Concise and direct" in prompt
    assert "Private owner preference" not in prompt
    assert "Private direct style" not in prompt
    assert "Response mode: draft_for_owner" in prompt
    assert "Draft-for-owner mode" in prompt
    assert "Do not disclose owner-private facts" in prompt


def test_correspondent_respond_on_behalf_requires_explicit_policy_opt_in():
    config = {
        **CONFIG,
        "policies": {
            "coworker": {
                "tools": {"allow": ["clarify"]},
                "digital_twin": {
                    "response_mode": "respond_on_behalf",
                    "allow_respond_on_behalf": True,
                },
            }
        },
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Response mode: respond_on_behalf" in prompt
    assert "Respond-on-behalf mode" in prompt
    assert "escalate commitments" in prompt


def test_unknown_response_mode_falls_back_to_assistant_mode():
    config = {
        **CONFIG,
        "policies": {
            "coworker": {
                "tools": {"allow": ["clarify"]},
                "digital_twin": {"response_mode": "owner_clone"},
            }
        },
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Response mode: answer_as_assistant" in prompt
    assert "Assistant mode" in prompt
    assert "owner_clone" not in prompt


def test_correspondent_gets_only_public_style_exemplars_and_confidence():
    config = {
        **CONFIG,
        "owners": {
            "owner": {
                **CONFIG["owners"]["owner"],
                "style_confidence": "low",
                "style_exemplars": ["Private owner phrase"],
                "public_style_exemplars": [
                    "Thanks for the context. I will take a look.",
                    {"text": "Short public reply example."},
                ],
            }
        },
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Style confidence: low" in prompt
    assert "Thanks for the context" in prompt
    assert "Short public reply example" in prompt
    assert "Private owner phrase" not in prompt


def test_owner_twin_prefers_honcho_private_context_when_exported():
    config = {
        **CONFIG,
        "honcho": {
            "digital_twin": {
                "owners": {
                    "owner": {
                        "private_profile": "Honcho private owner model",
                        "communication_style": "Honcho owner style",
                        "ai_representation": "Honcho assistant identity",
                    }
                }
            }
        },
    }
    ctx = PermissionResolver(config).resolve(_source("owner"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Honcho private owner model" in prompt
    assert "Honcho owner style" in prompt
    assert "Honcho assistant identity" in prompt
    assert "Preferred memory source: Honcho" in prompt
    assert "Private owner preference" not in prompt


def test_correspondent_only_gets_honcho_public_twin_fields():
    config = {
        **CONFIG,
        "honcho": {
            "digital_twin": {
                "owners": {
                    "owner": {
                        "private_profile": "Honcho private owner model",
                        "communication_style": "Honcho private style",
                        "public_profile": "Honcho public owner model",
                        "public_style": "Honcho public style",
                        "public_assistant_identity": "Public assistant role",
                    }
                }
            }
        },
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Honcho public owner model" in prompt
    assert "Honcho public style" in prompt
    assert "Public assistant role" in prompt
    assert "Preferred memory source: Honcho" in prompt
    assert "Honcho private owner model" not in prompt
    assert "Honcho private style" not in prompt


def test_correspondent_does_not_get_honcho_source_marker_for_private_only_context():
    config = {
        **CONFIG,
        "honcho": {
            "digital_twin": {
                "owners": {
                    "owner": {
                        "private_profile": "Honcho private owner model",
                        "communication_style": "Honcho private style",
                    }
                }
            }
        },
    }
    ctx = PermissionResolver(config).resolve(_source("employee"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Honcho private owner model" not in prompt
    assert "Honcho private style" not in prompt
    assert "Preferred memory source: Honcho" not in prompt


def test_malformed_honcho_twin_context_falls_back_to_owner_config():
    config = {
        **CONFIG,
        "honcho": {"digital_twin": {"owners": {"owner": "not-a-mapping"}}},
    }
    ctx = PermissionResolver(config).resolve(_source("owner"), session_key="s")

    prompt = assemble_owner_twin_context(config, ctx)

    assert "Private owner preference" in prompt
    assert "Private direct style" in prompt
    assert "Preferred memory source: Honcho" not in prompt
