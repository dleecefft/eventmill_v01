"""
Event Mill Cloud Abstraction Layer

Cloud-provider-specific code is isolated behind abstract interfaces
to enable future portability (GCP, AWS, Azure).
"""

from .interfaces import ConfigProvider, SecretProvider, StorageBackend

__all__ = [
    "ConfigProvider",
    "SecretProvider",
    "StorageBackend",
]
