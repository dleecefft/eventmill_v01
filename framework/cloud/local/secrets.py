"""
Local Secret Provider

Environment variable implementation of SecretProvider for development.
"""

from __future__ import annotations

import os
from typing import Any

from ..interfaces import SecretProvider, ConfigProvider


class EnvVarSecretProvider(SecretProvider):
    """Environment variable secret provider.
    
    Used for local development. Reads secrets from environment variables.
    """
    
    def __init__(self, prefix: str = "EVENTMILL_"):
        """Initialize environment variable secret provider.
        
        Args:
            prefix: Prefix for environment variable names.
        """
        self.prefix = prefix
    
    def get_secret(self, secret_name: str) -> str | None:
        """Get a secret from environment variables."""
        # Try with prefix first
        env_name = f"{self.prefix}{secret_name.upper()}"
        value = os.environ.get(env_name)
        
        if value is None:
            # Try without prefix
            value = os.environ.get(secret_name.upper())
        
        return value
    
    def get_secret_version(
        self,
        secret_name: str,
        version: str = "latest",
    ) -> str | None:
        """Get a secret (version is ignored for env vars)."""
        return self.get_secret(secret_name)


class EnvFileConfigProvider(ConfigProvider):
    """Configuration provider that reads from .env files and environment.
    
    Used for local development.
    """
    
    def __init__(
        self,
        env_file: str | None = None,
        prefix: str = "EVENTMILL_",
    ):
        """Initialize configuration provider.
        
        Args:
            env_file: Path to .env file (optional).
            prefix: Prefix for environment variable names.
        """
        self.env_file = env_file
        self.prefix = prefix
        self._config: dict[str, Any] = {}
        self.reload()
    
    def reload(self) -> None:
        """Reload configuration from environment."""
        self._config = {}
        
        # Load from .env file if specified
        if self.env_file and os.path.exists(self.env_file):
            self._load_env_file(self.env_file)
        
        # Load from environment variables with prefix
        for key, value in os.environ.items():
            if key.startswith(self.prefix):
                config_key = key[len(self.prefix):].lower()
                self._config[config_key] = self._parse_value(value)
    
    def _load_env_file(self, path: str) -> None:
        """Load variables from a .env file."""
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    
                    if key.startswith(self.prefix):
                        config_key = key[len(self.prefix):].lower()
                        self._config[config_key] = self._parse_value(value)
    
    def _parse_value(self, value: str) -> Any:
        """Parse a string value to appropriate type."""
        # Boolean
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        
        # String
        return value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        # Support dot-separated keys for nested access
        parts = key.lower().split(".")
        value = self._config
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def get_all(self) -> dict[str, Any]:
        """Get all configuration values."""
        return self._config.copy()
