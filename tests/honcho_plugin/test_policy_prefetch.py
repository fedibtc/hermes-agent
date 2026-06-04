from types import SimpleNamespace

from plugins.memory.honcho import HonchoMemoryProvider
from plugins.memory.honcho.client import HonchoClientConfig


class _NoFreshContext:
    def pop_context_result(self, session_key):
        return None


def _provider_with_cached_context(*, pin_peer_name: bool) -> HonchoMemoryProvider:
    provider = HonchoMemoryProvider()
    provider._config = HonchoClientConfig(
        api_key="test-key",
        enabled=True,
        pin_peer_name=pin_peer_name,
    )
    provider._manager = _NoFreshContext()
    provider._session_key = "honcho-session"
    provider._session_initialized = True
    provider._base_context_cache = "Private owner Honcho representation"
    provider._last_context_turn = 1
    provider._last_dialectic_turn = 1
    provider._turn_count = 1
    return provider


def test_pinned_honcho_context_is_suppressed_for_non_owner():
    provider = _provider_with_cached_context(pin_peer_name=True)
    ctx = SimpleNamespace(is_owner=False)

    assert provider.prefetch("summarize schedule", permission_context=ctx) == ""


def test_pinned_honcho_context_is_available_to_owner():
    provider = _provider_with_cached_context(pin_peer_name=True)
    ctx = SimpleNamespace(is_owner=True)

    assert "Private owner Honcho representation" in provider.prefetch(
        "summarize schedule",
        permission_context=ctx,
    )


def test_multi_user_honcho_context_is_not_suppressed_for_non_owner():
    provider = _provider_with_cached_context(pin_peer_name=False)
    ctx = SimpleNamespace(is_owner=False)

    assert "Private owner Honcho representation" in provider.prefetch(
        "summarize schedule",
        permission_context=ctx,
    )
