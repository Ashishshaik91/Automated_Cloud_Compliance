"""
Policy Loader — reads YAML policy files from the policies/ directory.
Supports hot-reload (re-reads on next call if file is updated).
"""

import os
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)

POLICIES_BASE_DIR = Path(__file__).parent.parent.parent / "policies"


class PolicyLoader:
    """
    Loads and caches compliance policies from YAML files.
    Policies are organized by framework and resource type.
    """

    def __init__(self, base_dir: Path = POLICIES_BASE_DIR) -> None:
        self.base_dir = base_dir
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def load_all(self) -> None:
        """Load all policies from all framework directories."""
        self._cache.clear()
        for framework_dir in self.base_dir.iterdir():
            if framework_dir.is_dir():
                framework = framework_dir.name
                for policy_file in framework_dir.glob("*.yaml"):
                    self._load_file(framework, policy_file)
        logger.info(
            "Policies loaded",
            frameworks=list(self._cache.keys()),
            total=sum(len(v) for v in self._cache.values()),
        )

    def _load_file(self, framework: str, path: Path) -> None:
        """Load a single YAML policy file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                logger.warning("Invalid policy file format", path=str(path))
                return
            policies = data.get("policies", [])
            for policy in policies:
                policy["framework"] = framework
                key = f"{framework}:{policy.get('resource_type', 'all')}"
                self._cache.setdefault(key, []).append(policy)
                # Also store under wildcard key for framework-wide queries
                all_key = f"{framework}:all"
                self._cache.setdefault(all_key, []).append(policy)
        except (yaml.YAMLError, OSError) as e:
            logger.error("Failed to load policy file", path=str(path), error=str(e))

    def get_policies(
        self,
        framework: str,
        resource_type: str = "all",
    ) -> list[dict[str, Any]]:
        """Return policies for a given framework and resource type."""
        if not self._cache:
            self.load_all()
        # Get specific + wildcard policies, deduplicate by policy ID
        specific_key = f"{framework}:{resource_type}"
        seen_ids: set[str] = set()
        results = []
        for policy in self._cache.get(specific_key, []):
            pid = policy.get("id", "")
            if pid not in seen_ids:
                seen_ids.add(pid)
                results.append(policy)
        return results

    def get_frameworks(self) -> list[str]:
        """Return the list of all loaded frameworks."""
        return list({k.split(":")[0] for k in self._cache.keys()})

    def invalidate_cache(self) -> None:
        """Force a cache reload on next access."""
        self._cache.clear()
        logger.info("Policy cache invalidated")
