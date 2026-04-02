# backend/app/integrations/__init__.py
"""
Threat Intelligence integrations package.

Modules:
  nvd_client           — NVD REST API v2 CPE-based CVE search
  virustotal_client    — VirusTotal v3 IP reputation (free tier with rate limiting)
  misp_client          — MISP threat event search (opt-in, disabled by default)
  threat_intel_cache   — Redis-backed 24h cache for all threat intel responses
"""
