"""
Azure Cloud Connector — stub with full interface.
Uses azure-mgmt libraries. Credentials from env vars (never hardcoded).
"""

import asyncio
from typing import Any

import structlog

from app.config import get_settings
from app.connectors.base import CloudConnectorBase
from app.models.compliance import CloudAccount

settings = get_settings()
logger = structlog.get_logger(__name__)


class AzureConnector(CloudConnectorBase):
    """Enumerates Azure resources for compliance checking."""

    def __init__(self, account: CloudAccount) -> None:
        super().__init__(account)
        self._credential = None

    def _get_credential(self):
        """Get Azure credential from environment variables."""
        from azure.identity import ClientSecretCredential
        return ClientSecretCredential(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret.get_secret_value(),
        )

    async def enumerate_resources(self, framework: str) -> list[dict[str, Any]]:
        """Enumerate Azure resources for compliance."""
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(None, self._get_storage_accounts),
            loop.run_in_executor(None, self._get_virtual_machines),
            loop.run_in_executor(None, self._get_sql_servers),
            loop.run_in_executor(None, self._get_key_vaults),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        resources: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("Azure enumeration error", error=str(r))
            else:
                resources.extend(r)  # type: ignore[arg-type]
        return resources

    async def get_resource_config(self, resource_id: str, resource_type: str) -> dict[str, Any]:
        return {}

    def _get_storage_accounts(self) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.storage import StorageManagementClient
            cred = self._get_credential()
            client = StorageManagementClient(cred, settings.azure_subscription_id)
            resources = []
            for account in client.storage_accounts.list():
                config = {
                    "name": account.name,
                    "https_only": account.enable_https_traffic_only,
                    "encryption_enabled": account.encryption is not None,
                    "allow_blob_public_access": getattr(account, "allow_blob_public_access", True),
                    "minimum_tls_version": getattr(account, "minimum_tls_version", "TLS1_0"),
                }
                resources.append(
                    self._normalize_resource(config, "azure_storage_account", account.name or "")
                )
            return resources
        except Exception as e:
            logger.error("Azure storage enumeration failed", error=str(e))
            return []

    def _get_virtual_machines(self) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.compute import ComputeManagementClient
            cred = self._get_credential()
            client = ComputeManagementClient(cred, settings.azure_subscription_id)
            resources = []
            for vm in client.virtual_machines.list_all():
                config = {
                    "vm_id": vm.vm_id,
                    "name": vm.name,
                    "location": vm.location,
                    "os_type": vm.storage_profile.os_disk.os_type if vm.storage_profile else None,
                }
                resources.append(
                    self._normalize_resource(config, "azure_vm", vm.name or "")
                )
            return resources
        except Exception as e:
            logger.error("Azure VM enumeration failed", error=str(e))
            return []

    def _get_sql_servers(self) -> list[dict[str, Any]]:
        """Enumerate Azure SQL Servers for compliance."""
        try:
            from azure.mgmt.sql import SqlManagementClient
            cred = self._get_credential()
            client = SqlManagementClient(cred, settings.azure_subscription_id)
            resources = []
            for server in client.servers.list():
                config = {
                    "name": server.name,
                    "location": server.location,
                    "administrator_login": server.administrator_login,
                    "minimal_tls_version": getattr(server, "minimal_tls_version", "None"),
                    "public_network_access": getattr(server, "public_network_access", "Enabled") == "Enabled",
                }
                resources.append(
                    self._normalize_resource(config, "azure_sql_server", server.name or "")
                )
            return resources
        except Exception as e:
            logger.error("Azure SQL enumeration failed", error=str(e))
            return []

    def _get_key_vaults(self) -> list[dict[str, Any]]:
        """Enumerate Azure Key Vaults."""
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            cred = self._get_credential()
            client = KeyVaultManagementClient(cred, settings.azure_subscription_id)
            resources = []
            for vault in client.vaults.list():
                config = {
                    "name": vault.name,
                    "location": vault.location,
                    "sku": vault.properties.sku.name if vault.properties and vault.properties.sku else None,
                    "soft_delete_enabled": getattr(vault.properties, "enable_soft_delete", False) if vault.properties else False,
                    "purge_protection": getattr(vault.properties, "enable_purge_protection", False) if vault.properties else False,
                }
                resources.append(
                    self._normalize_resource(config, "azure_key_vault", vault.name or "")
                )
            return resources
        except Exception as e:
            logger.error("Azure Key Vault enumeration failed", error=str(e))
            return []
