"""
Abstract base class for all cloud provider connectors.
All connectors must implement enumerate_resources().
"""

from abc import ABC, abstractmethod
from typing import Any

import structlog

from app.models.compliance import CloudAccount

logger = structlog.get_logger(__name__)


class CloudConnectorBase(ABC):
    """Abstract interface for cloud provider connectors."""

    def __init__(self, account: CloudAccount) -> None:
        self.account = account
        self.provider = account.provider
        self.account_id = account.account_id
        self.region = account.region or "us-east-1"

    @abstractmethod
    async def enumerate_resources(self, framework: str) -> list[dict[str, Any]]:
        """
        Enumerate all relevant cloud resources for the given compliance framework.
        Returns a list of resource dicts with at minimum:
        {
            resource_type: str,
            resource_id: str,
            region: str,
            ...provider-specific fields...
        }
        """
        ...

    @abstractmethod
    async def get_resource_config(self, resource_id: str, resource_type: str) -> dict[str, Any]:
        """Fetch the configuration of a specific resource."""
        ...

    def _normalize_resource(
        self,
        provider_data: dict[str, Any],
        resource_type: str,
        resource_id: str,
    ) -> dict[str, Any]:
        """Normalize provider-specific resource data into the unified schema."""
        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "raw": provider_data,
            **provider_data,  # merge provider fields at top level for easy rule access
        }
