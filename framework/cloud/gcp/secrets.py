"""
GCP Secret Provider

Google Cloud Secret Manager implementation of SecretProvider.
Requires: google-cloud-secret-manager
"""

from __future__ import annotations

import logging
from typing import Any

from ..interfaces import SecretProvider

logger = logging.getLogger("eventmill.framework.cloud.gcp")


class GCPSecretProvider(SecretProvider):
    """Google Cloud Secret Manager provider.
    
    Retrieves secrets from GCP Secret Manager.
    Requires the google-cloud-secret-manager package.
    """
    
    def __init__(
        self,
        project_id: str,
    ):
        """Initialize GCP secret provider.
        
        Args:
            project_id: GCP project ID.
        """
        self.project_id = project_id
        self._client = None
    
    def _get_client(self):
        """Lazy initialization of Secret Manager client."""
        if self._client is None:
            try:
                from google.cloud import secretmanager
                self._client = secretmanager.SecretManagerServiceClient()
                logger.info("Connected to GCP Secret Manager")
            except ImportError:
                raise ImportError(
                    "google-cloud-secret-manager package required. "
                    "Install with: pip install google-cloud-secret-manager"
                )
        return self._client
    
    def get_secret(self, secret_name: str) -> str | None:
        """Get a secret from GCP Secret Manager (latest version)."""
        return self.get_secret_version(secret_name, "latest")
    
    def get_secret_version(
        self,
        secret_name: str,
        version: str = "latest",
    ) -> str | None:
        """Get a specific version of a secret."""
        client = self._get_client()
        
        name = (
            f"projects/{self.project_id}/"
            f"secrets/{secret_name}/"
            f"versions/{version}"
        )
        
        try:
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("utf-8")
        except Exception as e:
            logger.warning("Failed to access secret %s: %s", secret_name, e)
            return None
