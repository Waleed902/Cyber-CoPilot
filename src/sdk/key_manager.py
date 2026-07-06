"""
API Key Session Manager
Handles multiple API keys with auto-rotation
"""

import os
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime
from loguru import logger
from openai import OpenAI, AsyncOpenAI


@dataclass
class APIKeyConfig:
    """Configuration for an API key."""
    name: str
    provider: str  # longcat, openrouter, openai, nvidia, modelscope
    api_key: str
    base_url: str
    model: str
    enabled: bool = True
    priority: int = 0  # Lower = higher priority
    
    # Usage tracking
    total_calls: int = 0
    total_tokens: int = 0
    last_used: str = ""
    last_error: str = ""
    consecutive_failures: int = 0
    rate_limited_until: Optional[float] = None


@dataclass
class SessionUsage:
    """Track usage for current session."""
    session_id: str
    started_at: str
    api_calls: int = 0
    total_tokens: int = 0
    keys_used: List[str] = field(default_factory=list)
    errors: List[Dict] = field(default_factory=list)


class APIKeyManager:
    """
    Manages API keys with automatic fallback and usage tracking.
    
    Features:
    - Multiple provider support (Longcat, OpenRouter, OpenAI, NVIDIA, ModelScope)
    - Automatic key rotation on failure
    - Usage tracking per key and session
    - Runtime key switching
    - Persistent storage of key stats
    """
    
    def __init__(self, config_path: str = "./.api_keys.json"):
        self.config_path = Path(config_path)
        self.keys: Dict[str, APIKeyConfig] = {}
        self.current_key: Optional[str] = None
        self.client: Optional[OpenAI] = None
        self.async_client: Optional[AsyncOpenAI] = None
        self.session: Optional[SessionUsage] = None
        self.default_provider: str = os.getenv("DEFAULT_PROVIDER", "").strip().lower()
        
        # Load existing config or create from env
        self._load_or_create_config()
        self._start_session()
    
    def _load_or_create_config(self):
        """Load config from environment. Always start fresh."""
        self._load_from_env()
        
        if not self.keys:
            logger.error(
                "No API keys configured! Set one of NVIDIA_API_KEY, OPENROUTER_API_KEY, "
                "or MODELSCOPE_API_KEY in .env"
            )
        
        # Select initial key
        self._select_best_key()
    
    def _load_from_env(self):
        """Load API keys from environment variables."""
        from src.sdk.model_settings import get_model_settings
        model_settings = get_model_settings()
        
        # Longcat
        longcat_model = (model_settings.get_model("longcat") or "").strip()
        if os.getenv("LONGCAT_API_KEY") and longcat_model:
            self.keys["longcat"] = APIKeyConfig(
                name="longcat",
                provider="longcat",
                api_key=os.getenv("LONGCAT_API_KEY"),
                base_url=os.getenv("LONGCAT_BASE_URL", "https://api.longcat.chat/openai"),
                model=longcat_model,
                priority=self._get_provider_priority("longcat")
            )
        elif os.getenv("LONGCAT_API_KEY"):
            logger.debug("Skipping LONGCAT_API_KEY because Longcat is disabled or LONGCAT_MODEL is not set.")

        # Longcat secondary key
        if os.getenv("LONGCAT_API_KEY_2") and longcat_model:
            self.keys["longcat2"] = APIKeyConfig(
                name="longcat2",
                provider="longcat",
                api_key=os.getenv("LONGCAT_API_KEY_2"),
                base_url=os.getenv("LONGCAT_BASE_URL", "https://api.longcat.chat/openai"),
                model=longcat_model,
                priority=self._get_provider_priority("longcat")
            )
        elif os.getenv("LONGCAT_API_KEY_2"):
            logger.debug("Skipping LONGCAT_API_KEY_2 because Longcat is disabled or LONGCAT_MODEL is not set.")
        
        # OpenRouter
        openrouter_model = (model_settings.get_model("openrouter") or "").strip()
        if os.getenv("OPENROUTER_API_KEY") and os.getenv("OPENROUTER_API_KEY") != "your_openrouter_key_here" and openrouter_model:
            self.keys["openrouter"] = APIKeyConfig(
                name="openrouter",
                provider="openrouter",
                api_key=os.getenv("OPENROUTER_API_KEY"),
                base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
                model=openrouter_model,
                priority=self._get_provider_priority("openrouter")
            )
        elif os.getenv("OPENROUTER_API_KEY") and os.getenv("OPENROUTER_API_KEY") != "your_openrouter_key_here":
            logger.warning("Skipping OPENROUTER_API_KEY because OPENROUTER_MODEL is empty.")

        # OpenAI
        openai_model = (model_settings.get_model("openai") or "").strip()
        if os.getenv("OPENAI_API_KEY") and openai_model:
            self.keys["openai"] = APIKeyConfig(
                name="openai",
                provider="openai",
                api_key=os.getenv("OPENAI_API_KEY"),
                base_url="https://api.openai.com/v1",
                model=openai_model,
                priority=self._get_provider_priority("openai")
            )
        elif os.getenv("OPENAI_API_KEY"):
            logger.debug("Skipping OPENAI_API_KEY because OpenAI is disabled or OPENAI_MODEL is empty.")
            
        # NVIDIA
        nvidia_key = os.getenv("NVIDIA_API_KEY")
        if nvidia_key:
            nvidia_model = (model_settings.get_model("nvidia") if hasattr(model_settings, 'get_model') else "").strip()
            self.keys["nvidia"] = APIKeyConfig(
                name="nvidia",
                provider="nvidia",
                api_key=nvidia_key,
                base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
                model=nvidia_model or "stepfun-ai/step-3.7-flash",
                priority=self._get_provider_priority("nvidia")
            )
        
        # ModelScope
        modelscope_model = (model_settings.get_model("modelscope") or "").strip()
        if os.getenv("MODELSCOPE_API_KEY") and modelscope_model:
            self.keys["modelscope"] = APIKeyConfig(
                name="modelscope",
                provider="modelscope",
                api_key=os.getenv("MODELSCOPE_API_KEY"),
                base_url=os.getenv("MODELSCOPE_BASE_URL", "https://api-inference.modelscope.ai/v1"),
                model=modelscope_model,
                priority=self._get_provider_priority("modelscope")
            )
        elif os.getenv("MODELSCOPE_API_KEY"):
            logger.warning("Skipping MODELSCOPE_API_KEY because MODELSCOPE_MODEL is empty.")

    def _get_provider_priority(self, provider: str) -> int:
        """Return priority for provider selection."""
        if self.default_provider and provider == self.default_provider:
            return -1
        fallback_order = {"nvidia": 0, "longcat": 1, "openrouter": 2, "openai": 3, "modelscope": 4}
        return fallback_order.get(provider, 10)
    
    def _select_best_key(self) -> bool:
        """Select the best available key based on priority and health."""
        now = time.time()
        available = [
            k for k in self.keys.values()
            if k.enabled
            and k.model.strip()
            and k.consecutive_failures < 3
            and (k.rate_limited_until is None or k.rate_limited_until <= now)
        ]
        if not available:
            # If every key is cooling down, keep the least-bad enabled key so the
            # caller can wait explicitly instead of losing provider state.
            available = [
                k for k in self.keys.values()
                if k.enabled and k.model.strip() and k.consecutive_failures < 3
            ]
        if not available:
            logger.error("No healthy API keys available!")
            return False
        available.sort(key=lambda k: (k.priority, k.consecutive_failures, k.name))
        best = available[0]
        self._switch_to_key(best.name)
        return True
    
    def _switch_to_key(self, key_name: str):
        """Switch to a specific API key."""
        if key_name not in self.keys:
            logger.error(f"Key '{key_name}' not found")
            return
        key = self.keys[key_name]
        if not key.model.strip():
            logger.error(f"Key '{key_name}' has no model configured; skipping")
            return
        extra_headers = {}
        if key.provider == "openrouter":
            extra_headers = {"HTTP-Referer": "https://cyber-copilot.local", "X-Title": "Cyber-CoPilot"}
        elif key.provider == "modelscope":
            # ModelScope/Aliyun WAF is extremely sensitive to content and bot-like signatures.
            # Using a browser-like User-Agent can sometimes help bypass superficial blocks.
            extra_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": "https://api-inference.modelscope.ai",
                "Referer": "https://api-inference.modelscope.ai/"
            }
        self.client = OpenAI(api_key=key.api_key, base_url=key.base_url, timeout=120.0, default_headers=extra_headers or None)
        self.async_client = AsyncOpenAI(api_key=key.api_key, base_url=key.base_url, timeout=120.0, default_headers=extra_headers or None)
        
        self._wrap_completions_with_reasoning_effort(self.client, is_async=False)
        self._wrap_completions_with_reasoning_effort(self.async_client, is_async=True)
        
        self.current_key = key_name
        logger.info(f"Switched to API key: {key_name} ({key.provider})")
    
    def _wrap_completions_with_reasoning_effort(self, client, is_async: bool):
        """Wrap the completion creation to inject reasoning_effort parameter."""
        original_create = client.chat.completions.create
        
        if is_async:
            async def async_create(*args, **kwargs):
                model_name = kwargs.get("model", "")
                model_lower = model_name.lower()
                is_reasoning = any(r in model_lower for r in ["step-", "glm", "o1-", "o3-", "deepseek-", "reasoning"])
                
                if is_reasoning and "reasoning_effort" not in kwargs:
                    if "thinking" in model_lower or "reasoning" in model_lower or "glm4.7" in model_lower or "step-3.7" in model_lower:
                        kwargs["reasoning_effort"] = "xhigh"
                    else:
                        kwargs["reasoning_effort"] = "high"
                
                try:
                    return await original_create(*args, **kwargs)
                except Exception as api_err:
                    if "reasoning_effort" in kwargs:
                        logger.debug(f"Retrying async completions without reasoning_effort due to: {api_err}")
                        del kwargs["reasoning_effort"]
                        return await original_create(*args, **kwargs)
                    else:
                        raise
            client.chat.completions.create = async_create
        else:
            def sync_create(*args, **kwargs):
                model_name = kwargs.get("model", "")
                model_lower = model_name.lower()
                is_reasoning = any(r in model_lower for r in ["step-", "glm", "o1-", "o3-", "deepseek-", "reasoning"])
                
                if is_reasoning and "reasoning_effort" not in kwargs:
                    if "thinking" in model_lower or "reasoning" in model_lower or "glm4.7" in model_lower or "step-3.7" in model_lower:
                        kwargs["reasoning_effort"] = "xhigh"
                    else:
                        kwargs["reasoning_effort"] = "high"
                
                try:
                    return original_create(*args, **kwargs)
                except Exception as api_err:
                    if "reasoning_effort" in kwargs:
                        logger.debug(f"Retrying sync completions without reasoning_effort due to: {api_err}")
                        del kwargs["reasoning_effort"]
                        return original_create(*args, **kwargs)
                    else:
                        raise
            client.chat.completions.create = sync_create
    
    def _start_session(self):
        self.session = SessionUsage(session_id=datetime.now().strftime("%Y%m%d_%H%M%S"), started_at=datetime.now().isoformat())
    
    def get_client(self) -> OpenAI:
        if not self.client: self._select_best_key()
        return self.client
    
    def get_async_client(self) -> AsyncOpenAI:
        if not self.async_client: self._select_best_key()
        return self.async_client
    
    def get_model(self) -> str:
        if self.current_key in self.keys: return self.keys[self.current_key].model
        from src.sdk.model_settings import get_model_settings
        default_provider = self.default_provider or os.getenv("DEFAULT_PROVIDER", "nvidia").strip().lower()
        settings = get_model_settings()
        return settings.get_model(default_provider) or settings.get_model("nvidia") or "stepfun-ai/step-3.7-flash"

    def get_current_provider(self) -> str:
        if self.current_key in self.keys: return self.keys[self.current_key].provider
        return "unknown"
    
    def record_success(self, tokens_used: int = 0):
        if not self.current_key: return
        key = self.keys[self.current_key]
        key.total_calls += 1
        key.total_tokens += tokens_used
        key.last_used = datetime.now().isoformat()
        key.consecutive_failures = 0
        if self.session:
            self.session.api_calls += 1
            self.session.total_tokens += tokens_used
            if self.current_key not in self.session.keys_used: self.session.keys_used.append(self.current_key)
        self._save_config()
    
    def record_failure(self, error: str) -> bool:
        if not self.current_key: return False
        previous_key = self.current_key
        key = self.keys[self.current_key]
        key.consecutive_failures += 1
        key.last_error = error
        error_lower = (error or "").lower()
        permanent_failure = any(
            marker in error_lower
            for marker in (
                "authentication failed",
                "invalid token",
                "invalid api key",
                "incorrect api key",
                "401",
                "no endpoints found",
                "unsupported model",
                "model field cannot be empty",
                "model_not_found",
                "does not exist",
            )
        )
        if "429" in error_lower or "too many requests" in error_lower or "rate limit" in error_lower:
            # NVIDIA and other hosted providers can return hard per-window 429s.
            # Cool this key down so supervisor/finding-extractor calls do not
            # immediately hammer the same exhausted provider.
            key.rate_limited_until = time.time() + min(300, 30 * key.consecutive_failures)
        if self.session: self.session.errors.append({"key": self.current_key, "error": error, "timestamp": datetime.now().isoformat()})
        if permanent_failure:
            logger.warning(f"Key '{self.current_key}' disabled after permanent provider/config error")
            key.enabled = False
        elif key.consecutive_failures >= 3:
            logger.warning(f"Key '{self.current_key}' disabled after 3 failures")
            key.enabled = False
        self._save_config()
        selected = self._select_best_key()
        return bool(selected and self.current_key != previous_key)
    
    def switch_provider(self, provider: str) -> bool:
        now = time.time()
        for name, key in self.keys.items():
            if (
                key.provider == provider
                and key.enabled
                and key.model.strip()
                and (key.rate_limited_until is None or key.rate_limited_until <= now)
            ):
                self._switch_to_key(name)
                return True
        return False
    
    def switch_model(self, provider: str, model_id: str) -> bool:
        from src.sdk.model_settings import get_model_settings
        get_model_settings().set_model(provider, model_id)
        for key in self.keys.values():
            if key.provider == provider:
                key.model = model_id
                key.enabled = True
                key.consecutive_failures = 0
                key.last_error = ""
                key.rate_limited_until = None
        return True
    
    async def wait_for_rate_limit_async(self, timeout: float = 60.0) -> bool:
        import asyncio
        if not self.current_key or self.current_key not in self.keys: return True
        key = self.keys[self.current_key]
        if key.rate_limited_until is None: return True
        waited = 0.0
        while time.time() < key.rate_limited_until:
            remaining = key.rate_limited_until - time.time()
            if waited >= timeout: return False
            sleep_for = min(1.0, remaining, timeout - waited)
            await asyncio.sleep(sleep_for)
            waited += sleep_for
        key.rate_limited_until = None
        return True

    def current_rate_limit_remaining(self) -> float:
        """Seconds remaining for the current key cooldown, or 0 if usable."""
        if not self.current_key or self.current_key not in self.keys:
            return 0.0
        until = self.keys[self.current_key].rate_limited_until
        if until is None:
            return 0.0
        remaining = until - time.time()
        if remaining <= 0:
            self.keys[self.current_key].rate_limited_until = None
            return 0.0
        return remaining

    def reset_keys(self) -> bool:
        """Re-enable configured keys and clear transient failure/cooldown state."""
        for key in self.keys.values():
            key.enabled = True
            key.consecutive_failures = 0
            key.last_error = ""
            key.rate_limited_until = None
        self.client = None
        self.async_client = None
        self._save_config()
        return self._select_best_key()

    def _save_config(self): pass

    def get_status(self) -> str:
        lines = ["╔══════════════════════════════════════════════════════════════", "║ API KEY STATUS", "╠══════════════════════════════════════════════════════════════"]
        for name, key in sorted(self.keys.items(), key=lambda x: x[1].priority):
            status = "✓ ACTIVE" if name == self.current_key else ("○ Ready" if key.enabled else "✗ Disabled")
            lines.append(f"║ {name:<12} │ {key.provider:<10} │ {status}")
            lines.append(f"║              │ Model: {key.model[:35]:<35}")
            lines.append(f"║              │ Calls: {key.total_calls:<5} │ Failures: {key.consecutive_failures}")
        if self.session:
            lines.append("╠══════════════════════════════════════════════════════════════")
            lines.append(f"║ SESSION: {self.session.api_calls} calls, {self.session.total_tokens} tokens")
        lines.append("╚══════════════════════════════════════════════════════════════")
        return "\n".join(lines)


_key_manager: Optional[APIKeyManager] = None
def get_key_manager() -> APIKeyManager:
    global _key_manager
    if _key_manager is None: _key_manager = APIKeyManager()
    return _key_manager
def reset_key_manager():
    global _key_manager
    _key_manager = None
    return get_key_manager()
