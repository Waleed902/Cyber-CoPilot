from src.sdk.runner import Runner
from src.sdk.scope import ScopeManager


class _ScopeStub:
    def _matches_entry(self, target, entry):
        scope_target = entry.target.lower()
        target = target.lower()
        return target == scope_target or target.endswith("." + scope_target)

    def is_in_scope(self, target):
        return target in {"api.example.com", "*.example.com"}


def test_active_target_allows_active_host_and_subdomain(monkeypatch):
    runner = object.__new__(Runner)
    monkeypatch.setattr("src.sdk.scope.get_scope_manager", lambda: _ScopeStub())

    assert runner._active_target_allows("example.com", "https://example.com/login")[0]
    assert runner._active_target_allows("example.com", "https://shop.example.com/cart")[0]


def test_active_target_blocks_unscoped_cross_host(monkeypatch):
    runner = object.__new__(Runner)
    monkeypatch.setattr("src.sdk.scope.get_scope_manager", lambda: _ScopeStub())

    allowed, message = runner._active_target_allows("example.com", "https://other.test/")

    assert not allowed
    assert "HOST GUARD BLOCKED" in message


def test_failure_pattern_classifies_repeated_api_denials():
    runner = object.__new__(Runner)

    assert runner._failure_pattern('{"code":"rest_cannot_edit","status":401}') == "rest_cannot_edit"
    assert runner._failure_pattern("Sorry, you are not allowed to edit this user.") == "not allowed to edit"


def test_summary_requests_trigger_cross_session_context_lookup():
    runner = object.__new__(Runner)

    assert runner._should_check_cross_session_context("[TARGET: gmuniversity.ac.in] summarise findings")
    assert runner._should_check_cross_session_context("summarize the findings for this target")
    assert runner._should_check_cross_session_context("give me a findings summary")


def test_ordinary_recon_request_does_not_trigger_cross_session_context_lookup():
    runner = object.__new__(Runner)

    assert not runner._should_check_cross_session_context("[TARGET: gmuniversity.ac.in] start recon")


def test_scope_metadata_persists(tmp_path):
    scope_path = tmp_path / ".scope.json"
    manager = ScopeManager(config_path=str(scope_path))

    manager.add_scope(
        "https://example.com",
        "in",
        notes="imported",
        program_url="https://bugcrowd.com/engagements/example",
        platform="bugcrowd.com",
        allowed_testing="safe testing",
        excluded_tests="dos",
        rate_limits="low",
        last_verified="2026-04-29T00:00:00",
    )

    reloaded = ScopeManager(config_path=str(scope_path))
    entry = reloaded.config.in_scope[0]
    assert entry.target == "example.com"
    assert entry.program_url == "https://bugcrowd.com/engagements/example"
    assert entry.platform == "bugcrowd.com"
    assert entry.excluded_tests == "dos"
