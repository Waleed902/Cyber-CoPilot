"""
Model Settings Manager
Allows selection of AI models for different providers
"""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from loguru import logger


@dataclass
class ModelConfig:
    """Configuration for an AI model."""
    id: str  # Model identifier for API calls
    name: str  # Human-readable name
    provider: str  # openrouter, longcat, openai, nvidia, modelscope
    is_free: bool = False
    description: str = ""


# Available models by provider
AVAILABLE_MODELS: Dict[str, List[ModelConfig]] = {
    "openrouter": [
        ModelConfig(
            id="cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
            name="Dolphin Mistral 24B (Venice)",
            provider="openrouter",
            is_free=True,
            description="Uncensored, great for pentesting"
        ),
        ModelConfig(
            id="nex-agi/nex-n2-pro:free",
            name="Nex N2 Pro",
            provider="openrouter",
            is_free=True,
            description="Nex AGI N2 Pro via OpenRouter"
        ),
        ModelConfig(
            id="google/gemma-4-31b-it:free",
            name="Gemma 4 31B IT",
            provider="openrouter",
            is_free=True,
            description="Google Gemma 4 31B IT via OpenRouter"
        ),
    ],
    # Longcat is temporarily disabled. Keep the provider key so old commands and
    # env files do not crash, but expose no selectable models for now.
    "longcat": [],
    # OpenAI is temporarily disabled. Keep the provider key so old commands and
    # env files do not crash, but expose no selectable models for now.
    "openai": [],
    "nvidia": [
        ModelConfig(
            id="minimaxai/minimax-m3",
            name="MiniMax M3",
            provider="nvidia",
            is_free=False,
            description="MiniMax M3 on NVIDIA"
        ),
        ModelConfig(
            id="stepfun-ai/step-3.7-flash",
            name="Step 3.7 Flash",
            provider="nvidia",
            is_free=False,
            description="StepFun Step 3.7 Flash on NVIDIA"
        ),
        ModelConfig(
            id="stepfun-ai/step-3.5-flash",
            name="Step 3.5 Flash",
            provider="nvidia",
            is_free=False,
            description="StepFun Step 3.5 Flash on NVIDIA"
        ),
        ModelConfig(
            id="mistralai/mistral-large-3-675b-instruct-2512",
            name="Mistral Large 3 675B Instruct",
            provider="nvidia",
            is_free=False,
            description="Mistral Large 3 675B Instruct on NVIDIA"
        ),
        ModelConfig(
            id="qwen/qwen3-coder-480b-a35b-instruct",
            name="Qwen 3 Coder 480B A35B Instruct",
            provider="nvidia",
            is_free=False,
            description="Qwen 3 Coder 480B A35B Instruct on NVIDIA"
        ),
        ModelConfig(
            id="deepseek-ai/deepseek-v4-flash",
            name="DeepSeek v4 Flash",
            provider="nvidia",
            is_free=False,
            description="DeepSeek v4 Flash on NVIDIA"
        ),
        ModelConfig(
            id="z-ai/glm-5.1",
            name="GLM 5.1",
            provider="nvidia",
            is_free=False,
            description="GLM 5.1 on NVIDIA"
        ),
        ModelConfig(
            id="moonshotai/kimi-k2.6",
            name="Kimi K2.6",
            provider="nvidia",
            is_free=False,
            description="Moonshot AI Kimi K2.6 on NVIDIA"
        ),
        ModelConfig(
            id="nvidia/nemotron-3-ultra-550b-a55b",
            name="Nemotron Ultra 550B A55B",
            provider="nvidia",
            is_free=False,
            description="NVIDIA Nemotron Ultra 550B A55B on NVIDIA"
        ),
        ModelConfig(
            id="deepseek-ai/deepseek-v4-pro",
            name="DeepSeek v4 Pro",
            provider="nvidia",
            is_free=False,
            description="DeepSeek v4 Pro on NVIDIA"
        ),
        ModelConfig(
            id="qwen/qwen3.5-397b-a17b",
            name="Qwen 3.5 397B A17B",
            provider="nvidia",
            is_free=False,
            description="Qwen 3.5 397B A17B on NVIDIA"
        ),
    ],
    "modelscope": [
        ModelConfig(
            id="deepseek-ai/DeepSeek-V4-Flash",
            name="DeepSeek V4 Flash",
            provider="modelscope",
            is_free=False,
            description="DeepSeek V4 Flash model on ModelScope"
        ),
        ModelConfig(
            id="zai-org/GLM-5.1",
            name="GLM 5.1 Reasoning",
            provider="modelscope",
            is_free=False,
            description="GLM 5.1 model with reasoning on ModelScope"
        ),
    ]
}


class ModelSettings:
    """
    Manages model selection for each provider.
    """
    
    def __init__(self):
        self.current_models: Dict[str, str] = {}
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default models from environment or use built-in defaults."""
        replacements = {
            "arcee-ai/trinity-large-preview:free": "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        }
        
        def _env_model(env_var: str, provider: str, default: str) -> str:
            val = os.getenv(env_var)
            if not val:
                return default
            val = val.strip()
            
            # Check if model is deprecated/replaced
            if val in replacements:
                repl = replacements[val]
                logger.warning(f"{val} is unavailable; falling back to {repl}. Update .env to remove this warning.")
                return repl
                
            # Check if model is in available models for the provider
            valid_ids = [m.id for m in AVAILABLE_MODELS.get(provider, [])]
            if val not in valid_ids and f"#{val}" not in valid_ids:
                logger.warning(f"{val} is unavailable; falling back to {default}. Update .env to remove this warning.")
                return default
                
            # If it is in the list but starts with #, it's deprecated/disabled
            if f"#{val}" in valid_ids or val.startswith("#"):
                logger.warning(f"{val} is unavailable; falling back to {default}. Update .env to remove this warning.")
                return default
                
            return val

        # OpenRouter - default to Venice while allowing other catalog models.
        self.current_models["openrouter"] = _env_model(
            "OPENROUTER_MODEL",
            "openrouter",
            "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"
        )
        
        # Longcat is disabled until the provider is re-enabled in AVAILABLE_MODELS.
        self.current_models["longcat"] = _env_model(
            "LONGCAT_MODEL",
            "longcat",
            ""
        )

        # OpenAI is disabled until the provider is re-enabled in AVAILABLE_MODELS.
        self.current_models["openai"] = _env_model(
            "OPENAI_MODEL",
            "openai",
            ""
        )
        
        # NVIDIA
        self.current_models["nvidia"] = _env_model(
            "NVIDIA_MODEL",
            "nvidia",
            "stepfun-ai/step-3.7-flash"
        )

        # ModelScope
        self.current_models["modelscope"] = _env_model(
            "MODELSCOPE_MODEL",
            "modelscope",
            "deepseek-ai/DeepSeek-V4-Flash"
        )
    
    def get_model(self, provider: str) -> str:
        """Get the current model for a provider."""
        return self.current_models.get(provider) or self.current_models.get("nvidia", "stepfun-ai/step-3.7-flash")

    def get_thinking_model(self, provider: str) -> str:
        """
        Get the reasoning/thinking model for a provider.

        This model is used for high-quality, deliberate reasoning tasks such as
        supervisor checks and attack planning — where slower but deeper thinking
        is preferable over a fast chat model.

        Falls back to the standard model if no thinking model is configured.
        """
        if provider == "longcat":
            return os.getenv("LONGCAT_THINKING_MODEL") or self.current_models.get("longcat", self.get_model(provider))
        if provider == "openrouter":
            return os.getenv("OPENROUTER_THINKING_MODEL") or self.current_models.get("openrouter", self.get_model(provider))
        if provider == "openai":
            return os.getenv("OPENAI_THINKING_MODEL") or self.current_models.get("openai", self.get_model(provider))
        if provider == "nvidia":
            return os.getenv("NVIDIA_THINKING_MODEL") or self.current_models.get("nvidia", self.get_model(provider))
        if provider == "modelscope":
            return os.getenv("MODELSCOPE_THINKING_MODEL") or self.current_models.get("modelscope", self.get_model(provider))
        return self.get_model(provider)
    
    def find_provider_for_model(self, model_id: str) -> Optional[str]:
        """
        Find which provider a model ID belongs to.
        Args:
            model_id: The model identifier string
        Returns:
            Provider name (openrouter, longcat, openai, nvidia, modelscope) or None if not found
        """
        for provider, models in AVAILABLE_MODELS.items():
            for m in models:
                if m.id == model_id or m.id == f"#{model_id}":
                    return provider
        return None

    def set_model(self, provider: str, model_id: str) -> bool:
        """Set the model for a provider."""
        # Validate model exists
        if provider in AVAILABLE_MODELS:
            valid_ids = [m.id for m in AVAILABLE_MODELS[provider]]
            if model_id in valid_ids or f"#{model_id}" in valid_ids:
                # If model is deprecated/prefixed with #, normalize it
                clean_id = model_id.lstrip("#")
                self.current_models[provider] = clean_id
                logger.info(f"Set {provider} model to: {clean_id}")
                return True
            else:
                # Allow custom model IDs
                logger.warning(f"Model {model_id} not in known list, but allowing anyway")
                self.current_models[provider] = model_id
                return True
        return False
    
    def list_models(self, provider: str = None, free_only: bool = False) -> List[ModelConfig]:
        """List available models, optionally filtered."""
        models = []
        
        providers = [provider] if provider else AVAILABLE_MODELS.keys()
        
        for p in providers:
            if p in AVAILABLE_MODELS:
                for m in AVAILABLE_MODELS[p]:
                    if free_only and not m.is_free:
                        continue
                    models.append(m)
        
        return models
    
    def get_model_info(self, provider: str) -> Optional[ModelConfig]:
        """Get info about the currently selected model."""
        model_id = self.current_models.get(provider)
        if not model_id:
            return None
        
        if provider in AVAILABLE_MODELS:
            for m in AVAILABLE_MODELS[provider]:
                if m.id == model_id or m.id == f"#{model_id}":
                    return m
        
        # Return basic info for custom models
        return ModelConfig(id=model_id, name=model_id, provider=provider)
    
    def get_status(self) -> str:
        """Get formatted status of current model settings."""
        lines = [
            "╔══════════════════════════════════════════════════════════════",
            "║ 🤖 MODEL SETTINGS",
            "╠══════════════════════════════════════════════════════════════"
        ]
        
        for provider, model_id in self.current_models.items():
            if not model_id:
                continue
            info = self.get_model_info(provider)
            if info:
                free_tag = "[FREE]" if info.is_free else "[PAID]"
                lines.append(f"║ {provider.upper():<12} │ {info.name[:30]:<30} {free_tag}")
            else:
                lines.append(f"║ {provider.upper():<12} │ {model_id[:30]:<30}")
        
        lines.append("╚══════════════════════════════════════════════════════════════")
        return "\n".join(lines)


# Global instance
_model_settings: Optional[ModelSettings] = None


def get_model_settings() -> ModelSettings:
    """Get or create the global model settings."""
    global _model_settings
    if _model_settings is None:
        _model_settings = ModelSettings()
    return _model_settings
