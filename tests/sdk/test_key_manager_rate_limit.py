import time

from src.sdk.key_manager import APIKeyConfig, APIKeyManager


def _manager_with_keys() -> APIKeyManager:
    manager = object.__new__(APIKeyManager)
    manager.keys = {
        "nvidia": APIKeyConfig(
            name="nvidia",
            provider="nvidia",
            api_key="k1",
            base_url="https://integrate.api.nvidia.com/v1",
            model="stepfun-ai/step-3.5-flash",
            priority=0,
        ),
        "openrouter": APIKeyConfig(
            name="openrouter",
            provider="openrouter",
            api_key="k2",
            base_url="https://openrouter.ai/api/v1",
            model="test-model",
            priority=1,
        ),
    }
    manager.current_key = "nvidia"
    manager.client = None
    manager.async_client = None
    manager.session = None
    manager._save_config = lambda: None
    manager._switch_to_key = lambda key_name: setattr(manager, "current_key", key_name)
    return manager


def _manager_with_blank_model_key() -> APIKeyManager:
    manager = _manager_with_keys()
    manager.keys["longcat"] = APIKeyConfig(
        name="longcat",
        provider="longcat",
        api_key="k3",
        base_url="https://api.longcat.chat/openai",
        model="",
        priority=-1,
    )
    return manager


def test_record_failure_cools_down_429_key_and_switches_provider():
    manager = _manager_with_keys()

    switched = manager.record_failure("Error code: 429 - Too Many Requests")

    assert switched is True
    assert manager.current_key == "openrouter"
    assert manager.keys["nvidia"].rate_limited_until > time.time()


def test_select_best_key_skips_rate_limited_provider():
    manager = _manager_with_keys()
    manager.keys["nvidia"].rate_limited_until = time.time() + 120

    assert manager._select_best_key() is True
    assert manager.current_key == "openrouter"


def test_select_best_key_skips_blank_model_provider():
    manager = _manager_with_blank_model_key()

    assert manager._select_best_key() is True
    assert manager.current_key == "nvidia"


def test_switch_provider_rejects_blank_model_key():
    manager = _manager_with_blank_model_key()

    assert manager.switch_provider("longcat") is False
    assert manager.current_key == "nvidia"


def test_switch_provider_rejects_rate_limited_key():
    manager = _manager_with_keys()
    manager.current_key = "openrouter"
    manager.keys["nvidia"].rate_limited_until = time.time() + 120

    assert manager.switch_provider("nvidia") is False
    assert manager.current_key == "openrouter"


def test_reset_keys_reenables_disabled_key_and_clears_cooldown():
    manager = _manager_with_keys()
    manager.keys["nvidia"].enabled = False
    manager.keys["nvidia"].consecutive_failures = 3
    manager.keys["nvidia"].last_error = "429"
    manager.keys["nvidia"].rate_limited_until = time.time() + 120
    manager.current_key = "openrouter"

    assert manager.reset_keys() is True
    assert manager.keys["nvidia"].enabled is True
    assert manager.keys["nvidia"].consecutive_failures == 0
    assert manager.keys["nvidia"].last_error == ""
    assert manager.keys["nvidia"].rate_limited_until is None
    assert manager.current_key == "nvidia"


def test_record_failure_disables_auth_error_immediately():
    manager = _manager_with_keys()
    manager.current_key = "openrouter"

    switched = manager.record_failure("Error code: 401 - Authentication failed, invalid token")

    assert switched is True
    assert manager.keys["openrouter"].enabled is False
    assert manager.current_key == "nvidia"


def test_record_failure_disables_unavailable_model_immediately():
    manager = _manager_with_keys()
    manager.current_key = "openrouter"

    switched = manager.record_failure("No endpoints found for arcee-ai/trinity-large-preview:free")

    assert switched is True
    assert manager.keys["openrouter"].enabled is False
    assert manager.current_key == "nvidia"
