"""
Compliance-as-Code (CaC) Engine.

Translates YAML policy definitions into executable checks and
evaluates them against cloud resource data via OPA (Open Policy Agent).
"""

import json
from typing import Any

import httpx
import structlog

from app.config import get_settings
from app.core.policy_loader import PolicyLoader

settings = get_settings()
logger = structlog.get_logger(__name__)


class CaCEngine:
    """
    Core engine that:
    1. Loads YAML policies from disk
    2. Sends resource data to OPA for policy evaluation
    3. Returns structured compliance check results
    """

    def __init__(self, policy_loader: PolicyLoader) -> None:
        self.policy_loader = policy_loader
        # OPA runs with TLS using a self-signed cert (generated alongside nginx certs).
        # The backend mounts the opa_ca_cert named volume at /app/certs — this volume
        # contains ONLY cert.pem (the CA cert for verifying OPA's TLS connection).
        # The OPA private key is NEVER present in this volume.
        # OPA_TLS_CA_CERT env var overrides the path for non-Docker environments.
        # Falls back to system CA store if the file doesn't exist — never uses verify=False.
        import os
        from pathlib import Path
        opa_cert_path = os.environ.get("OPA_TLS_CA_CERT", "/app/certs/cert.pem")
        tls_verify: str | bool = opa_cert_path if Path(opa_cert_path).exists() else True
        self._opa_client = httpx.AsyncClient(
            base_url=settings.opa_url,
            timeout=30.0,
            verify=tls_verify,
        )

    async def evaluate(
        self,
        framework: str,
        resource_type: str,
        resource_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Evaluate a cloud resource against all policies for the given framework.

        Returns a list of check result dicts:
        {
            policy_id, policy_name, framework, status, severity,
            resource_type, resource_id, details, remediation_hint
        }
        """
        policies = self.policy_loader.get_policies(framework, resource_type)
        results = []

        for policy in policies:
            result = await self._evaluate_policy(policy, resource_data)
            results.append(result)

        return results

    async def _evaluate_policy(
        self,
        policy: dict[str, Any],
        resource_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a single policy against resource data using OPA."""
        policy_id = policy.get("id", "unknown")
        policy_name = policy.get("name", "Unknown Policy")
        framework = policy.get("framework", "unknown")
        severity = policy.get("severity", "medium")
        opa_package = policy.get("opa_package", "compliance.generic")

        input_data = {
            "input": {
                "resource": resource_data,
                "policy": policy,
            }
        }

        try:
            response = await self._opa_client.post(
                f"/v1/data/{opa_package.replace('.', '/')}/allow",
                content=json.dumps(input_data),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            opa_result = response.json()
            allowed = opa_result.get("result", False)
            status = "pass" if allowed else "fail"
        except httpx.HTTPError as e:
            logger.error("OPA evaluation error", policy_id=policy_id, error=str(e))
            status = "error"

        # If OPA is not available, fall back to local Python evaluation
        if status == "error":
            status = self._local_fallback_eval(policy, resource_data)

        return {
            "policy_id": policy_id,
            "policy_name": policy_name,
            "framework": framework,
            "status": status,
            "severity": severity,
            "resource_type": resource_data.get("resource_type", "unknown"),
            "resource_id": resource_data.get("resource_id", "unknown"),
            "details": {"resource_data": resource_data},
            "remediation_hint": policy.get("remediation", ""),
        }

    def _local_fallback_eval(
        self,
        policy: dict[str, Any],
        resource_data: dict[str, Any],
    ) -> str:
        """
        Local Python fallback evaluator for simple conditions
        when OPA is unavailable.
        Supports basic rule syntax: field comparisons.
        """
        rules = policy.get("rules", [])
        for rule in rules:
            field = rule.get("field", "")
            operator = rule.get("operator", "equals")
            expected = rule.get("value")
            actual = resource_data.get(field)

            if operator == "equals" and actual != expected:
                return "fail"
            elif operator == "not_equals" and actual == expected:
                return "fail"
            elif operator == "contains" and expected not in str(actual):
                return "fail"
            elif operator == "exists" and actual is None:
                return "fail"
            elif operator == "is_true" and actual is not True:
                return "fail"
            elif operator == "is_false" and actual is not False:
                return "fail"
        return "pass"

    async def close(self) -> None:
        await self._opa_client.aclose()
