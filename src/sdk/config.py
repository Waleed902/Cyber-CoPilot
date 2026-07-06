"""
Centralized Configuration Management

Provides a single source of truth for all configuration settings
with validation, environment profiles, and hot-reload support.
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger


class Environment(Enum):
    """Environment profiles."""
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"


@dataclass
class APIConfig:
    """API configuration."""
    longcat_api_key: Optional[str] = None
    longcat_model: str = ""
    nvidia_api_key: Optional[str] = None
    nvidia_model: str = "stepfun-ai/step-3.7-flash"
    openrouter_api_key: Optional[str] = None
    openrouter_model: str = "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"
    openai_api_key: Optional[str] = None
    openai_model: str = ""
    modelscope_api_key: Optional[str] = None
    modelscope_model: str = "deepseek-ai/DeepSeek-V4-Flash"
    default_provider: str = "nvidia"
    
    # Rate limiting
    max_requests_per_minute: int = 60
    max_tokens_per_minute: int = 100000
    
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 2.0
    
    def validate(self) -> List[str]:
        """Validate API configuration."""
        errors = []
        valid_providers = ["nvidia", "longcat", "openrouter", "openai", "modelscope"]
        
        # Check at least one API key is set
        if not any([
            self.nvidia_api_key,
            self.longcat_api_key,
            self.openrouter_api_key,
            self.openai_api_key,
            self.modelscope_api_key,
        ]):
            errors.append("At least one API key must be configured")
        
        # Validate default provider
        if self.default_provider not in valid_providers:
            errors.append(f"Invalid default_provider: {self.default_provider}")
        
        # Check default provider has a key
        if self.default_provider == "nvidia" and not self.nvidia_api_key:
            errors.append("NVIDIA API key required when it's the default provider")
        elif self.default_provider == "longcat" and (not self.longcat_api_key or not self.longcat_model):
            errors.append("Longcat API key and model required when it's the default provider")
        elif self.default_provider == "openrouter" and not self.openrouter_api_key:
            errors.append("OpenRouter API key required when it's the default provider")
        elif self.default_provider == "openai" and (not self.openai_api_key or not self.openai_model):
            errors.append("OpenAI API key and model required when it's the default provider")
        elif self.default_provider == "modelscope" and not self.modelscope_api_key:
            errors.append("ModelScope API key required when it's the default provider")
        
        return errors


@dataclass
class RunnerConfig:
    """Runner/execution configuration."""
    max_iterations: int = 100
    max_tool_timeout: int = 3600  # 60 minutes (increased to allow long scans)
    require_confirmation: bool = False
    enable_recovery: bool = True
    show_detailed_output: bool = True
    
    # Loop detection (aligned with SmartLoopDetector defaults in loop_detector.py)
    max_exact_repeats: int = 8
    max_alternating_cycles: int = 6
    no_progress_threshold: int = 120
    
    # Self-reflection: agent pauses every N iterations to review its approach
    reflection_interval: int = 15  # Inject reflection prompt every 15 iterations
    
    # Context management
    max_context_tokens: int = 120000
    context_trim_threshold: int = 100000
    
    def validate(self) -> List[str]:
        """Validate runner configuration."""
        errors = []
        
        if self.max_iterations < 1:
            errors.append("max_iterations must be at least 1")
        
        if self.max_tool_timeout < 10:
            errors.append("max_tool_timeout must be at least 10 seconds")
        
        if self.max_context_tokens < 10000:
            errors.append("max_context_tokens must be at least 10000")
        
        return errors


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    cache_dir: str = "./.cache"
    max_size: int = 1000
    
    # Default TTLs (seconds)
    default_ttl: int = 900  # 15 minutes
    long_ttl: int = 86400  # 24 hours
    short_ttl: int = 300  # 5 minutes
    
    # Tool-specific TTLs
    tool_ttls: Dict[str, int] = field(default_factory=lambda: {
        "whois_lookup": 86400,
        "dig_lookup": 3600,
        "nmap_scan": 1800,
        "subfinder_enum": 1800,
        "nuclei_scan": 600,
        "sqlmap_attack": 0,  # Never cache
        "curl_request": 0,
    })
    
    def validate(self) -> List[str]:
        """Validate cache configuration."""
        errors = []
        
        if self.max_size < 10:
            errors.append("max_size must be at least 10")
        
        if self.default_ttl < 0:
            errors.append("default_ttl cannot be negative")
        
        return errors


@dataclass
class MemoryConfig:
    """Memory/database configuration."""
    enabled: bool = True
    persist_dir: str = "./.memory"
    use_chromadb: bool = True
    
    # Backup settings
    auto_backup: bool = True
    max_backups: int = 3
    backup_interval_hours: int = 24
    
    # Memory limits
    max_memories_per_target: int = 1000
    max_memory_age_days: int = 90
    
    def validate(self) -> List[str]:
        """Validate memory configuration."""
        errors = []
        
        if self.max_backups < 1:
            errors.append("max_backups must be at least 1")
        
        if self.max_backups > 10:
            errors.append("max_backups should not exceed 10")
        
        if self.max_memories_per_target < 100:
            errors.append("max_memories_per_target must be at least 100")
        
        return errors


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file_level: str = "DEBUG"
    log_dir: str = "./logs"
    log_file: str = "cyber_copilot.log"
    rotation: str = "10 MB"
    retention: str = "7 days"
    
    # Verbosity levels
    verbosity: str = "normal"  # quiet, normal, verbose
    
    def validate(self) -> List[str]:
        """Validate logging configuration."""
        errors = []
        
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.level not in valid_levels:
            errors.append(f"Invalid log level: {self.level}")
        
        if self.file_level not in valid_levels:
            errors.append(f"Invalid file_level: {self.file_level}")
        
        if self.verbosity not in ["quiet", "normal", "verbose"]:
            errors.append(f"Invalid verbosity: {self.verbosity}")
        
        return errors


@dataclass
class SecurityConfig:
    """Security configuration."""
    scope_checking_enabled: bool = True
    strict_mode: bool = False
    prompt_unknown_targets: bool = True
    
    # Tool restrictions
    dangerous_tools_require_confirm: bool = True
    dangerous_tools: List[str] = field(default_factory=lambda: [
        "sqlmap_attack",
        "metasploit_run",
        "hydra_bruteforce",
        "mimikatz_run",
    ])
    
    def validate(self) -> List[str]:
        """Validate security configuration."""
        # No validation errors for security config
        return []


@dataclass
class Config:
    """Main configuration container."""
    environment: Environment = Environment.DEVELOPMENT
    api: APIConfig = field(default_factory=APIConfig)
    runner: RunnerConfig = field(default_factory=RunnerConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    def validate(self) -> List[str]:
        """Validate entire configuration."""
        errors = []
        errors.extend(self.api.validate())
        errors.extend(self.runner.validate())
        errors.extend(self.cache.validate())
        errors.extend(self.memory.validate())
        errors.extend(self.logging.validate())
        errors.extend(self.security.validate())
        return errors
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'environment': self.environment.value,
            'api': asdict(self.api),
            'runner': asdict(self.runner),
            'cache': asdict(self.cache),
            'memory': asdict(self.memory),
            'logging': asdict(self.logging),
            'security': asdict(self.security),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Config':
        """Create from dictionary."""
        api_data = {
            key: value
            for key, value in dict(data.get('api', {})).items()
            if key in APIConfig.__dataclass_fields__
        }
        return cls(
            environment=Environment(data.get('environment', 'development')),
            api=APIConfig(**api_data),
            runner=RunnerConfig(**data.get('runner', {})),
            cache=CacheConfig(**data.get('cache', {})),
            memory=MemoryConfig(**data.get('memory', {})),
            logging=LoggingConfig(**data.get('logging', {})),
            security=SecurityConfig(**data.get('security', {})),
        )


class ConfigManager:
    """
    Manages configuration loading, validation, and hot-reload.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path("./.config/config.json")
        self.config: Config = Config()
        self._last_modified: Optional[float] = None
        self._watchers: List[callable] = []
    
    def load(self) -> Config:
        """Load configuration from file and environment."""
        # Load from file if exists
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    data = json.load(f)
                self.config = Config.from_dict(data)
                self._last_modified = self.config_path.stat().st_mtime
                logger.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.error(f"Failed to load config file: {e}")
        
        # Override with environment variables
        self._load_from_env()
        self._normalize_default_provider()
        
        # Validate
        errors = self.config.validate()
        if errors:
            logger.error(f"Configuration validation errors: {errors}")
            raise ValueError(f"Invalid configuration: {', '.join(errors)}")
        
        logger.info(f"Configuration loaded successfully (env: {self.config.environment.value})")
        return self.config
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        # API keys
        if os.getenv("NVIDIA_API_KEY"):
            self.config.api.nvidia_api_key = os.getenv("NVIDIA_API_KEY")
        if os.getenv("NVIDIA_MODEL"):
            self.config.api.nvidia_model = os.getenv("NVIDIA_MODEL")

        if os.getenv("LONGCAT_API_KEY"):
            self.config.api.longcat_api_key = os.getenv("LONGCAT_API_KEY")
        if os.getenv("LONGCAT_MODEL"):
            self.config.api.longcat_model = os.getenv("LONGCAT_MODEL")
        
        if os.getenv("OPENROUTER_API_KEY"):
            self.config.api.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        if os.getenv("OPENROUTER_MODEL"):
            self.config.api.openrouter_model = os.getenv("OPENROUTER_MODEL")

        if os.getenv("OPENAI_API_KEY"):
            self.config.api.openai_api_key = os.getenv("OPENAI_API_KEY")
        if os.getenv("OPENAI_MODEL"):
            self.config.api.openai_model = os.getenv("OPENAI_MODEL")
        
        if os.getenv("MODELSCOPE_API_KEY"):
            self.config.api.modelscope_api_key = os.getenv("MODELSCOPE_API_KEY")
        if os.getenv("MODELSCOPE_MODEL"):
            self.config.api.modelscope_model = os.getenv("MODELSCOPE_MODEL")

        
        if os.getenv("DEFAULT_PROVIDER"):
            self.config.api.default_provider = os.getenv("DEFAULT_PROVIDER")
        
        # Environment
        if os.getenv("ENVIRONMENT"):
            try:
                self.config.environment = Environment(os.getenv("ENVIRONMENT"))
            except ValueError:
                logger.warning(f"Invalid ENVIRONMENT value: {os.getenv('ENVIRONMENT')}")
        
        # Runner settings
        if os.getenv("MAX_ITERATIONS"):
            try:
                self.config.runner.max_iterations = int(os.getenv("MAX_ITERATIONS"))
            except ValueError:
                pass
        
        # Logging
        if os.getenv("LOG_LEVEL"):
            self.config.logging.level = os.getenv("LOG_LEVEL")
        
        if os.getenv("VERBOSITY"):
            self.config.logging.verbosity = os.getenv("VERBOSITY")

    def _normalize_default_provider(self):
        """Select a valid default provider when config/env is stale or incomplete."""
        configured = []
        if self.config.api.nvidia_api_key:
            configured.append("nvidia")
        if self.config.api.longcat_api_key and self.config.api.longcat_model:
            configured.append("longcat")
        if self.config.api.openrouter_api_key:
            configured.append("openrouter")
        if self.config.api.openai_api_key and self.config.api.openai_model:
            configured.append("openai")
        if self.config.api.modelscope_api_key:
            configured.append("modelscope")

        if not configured:
            return

        current = (self.config.api.default_provider or "").strip().lower()
        if current in configured:
            self.config.api.default_provider = current
            return

        preferred_order = ["nvidia", "openrouter", "modelscope", "longcat", "openai"]
        for provider in preferred_order:
            if provider in configured:
                self.config.api.default_provider = provider
                return
    
    def save(self, path: Optional[Path] = None):
        """Save configuration to file."""
        save_path = path or self.config_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(save_path, 'w') as f:
                json.dump(self.config.to_dict(), f, indent=2)
            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def reload(self) -> bool:
        """
        Reload configuration if file has changed.
        
        Returns:
            True if reloaded, False if no changes
        """
        if not self.config_path.exists():
            return False
        
        current_mtime = self.config_path.stat().st_mtime
        if self._last_modified and current_mtime <= self._last_modified:
            return False
        
        logger.info("Configuration file changed, reloading...")
        self.load()
        
        # Notify watchers
        for watcher in self._watchers:
            try:
                watcher(self.config)
            except Exception as e:
                logger.error(f"Config watcher error: {e}")
        
        return True
    
    def watch(self, callback: callable):
        """Register a callback for configuration changes."""
        self._watchers.append(callback)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot-notation key."""
        parts = key.split('.')
        value = self.config
        
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set a configuration value by dot-notation key."""
        parts = key.split('.')
        obj = self.config
        
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                raise KeyError(f"Invalid config key: {key}")
        
        if hasattr(obj, parts[-1]):
            setattr(obj, parts[-1], value)
        else:
            raise KeyError(f"Invalid config key: {key}")


# Global config manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get or create the global config manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
        _config_manager.load()
    return _config_manager


def get_config() -> Config:
    """Get the current configuration."""
    return get_config_manager().config


def reload_config() -> bool:
    """Reload configuration from file."""
    return get_config_manager().reload()
