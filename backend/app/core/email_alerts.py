"""
email_alerts.py — Rich HTML compliance alert emails.

Called after every scan completes. Sends one consolidated email per scan
summarising the score, framework, critical/high failures, and the top
failing checks so the recipient has full context without logging into
the platform.
"""

from __future__ import annotations

import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── HTML email template ──────────────────────────────────────────────────────

def _score_color(score: float) -> str:
    if score >= 80:
        return "#10b981"   # green
    if score >= 60:
        return "#f59e0b"   # amber
    return "#ef4444"       # red


def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def build_scan_email_html(
    account_name: str,
    provider: str,
    framework: str,
    score: float,
    total_checks: int,
    passed_checks: int,
    failed_checks: int,
    critical_count: int,
    high_count: int,
    top_failures: list[dict],   # list of {policy_name, severity, resource_id}
    scan_id: int,
    scan_time: str,
) -> tuple[str, str]:
    """Return (subject, html_body) for a scan result email."""

    grade    = _grade(score)
    sc_color = _score_color(score)
    status   = "PASS" if score >= 70 else "FAIL"
    status_color = "#10b981" if status == "PASS" else "#ef4444"

    sev_badge = {
        "critical": ("background:#ef444433;color:#ef4444", "CRITICAL"),
        "high":     ("background:#f59e0b33;color:#f59e0b", "HIGH"),
        "medium":   ("background:#0ea5e933;color:#0ea5e9", "MEDIUM"),
        "low":      ("background:#6b728033;color:#9ca3af", "LOW"),
    }

    failures_rows = ""
    for f in top_failures[:10]:
        sev    = (f.get("severity") or "medium").lower()
        style, label = sev_badge.get(sev, sev_badge["medium"])
        res    = f.get("resource_id") or "—"
        policy = f.get("policy_name") or "Unknown policy"
        failures_rows += f"""
        <tr>
          <td style="padding:10px 12px;border-bottom:1px solid #1e293b;font-family:'JetBrains Mono',monospace;font-size:12px;color:#94a3b8;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{policy}</td>
          <td style="padding:10px 12px;border-bottom:1px solid #1e293b;font-family:'JetBrains Mono',monospace;font-size:11px;color:#64748b;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{res}</td>
          <td style="padding:10px 12px;border-bottom:1px solid #1e293b;text-align:center">
            <span style="padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;{style}">{label}</span>
          </td>
        </tr>"""

    no_failures_row = "" if failures_rows else """
        <tr><td colspan="3" style="padding:24px;text-align:center;color:#4b5563;font-family:monospace;font-size:13px">
          [ NO CRITICAL / HIGH FAILURES DETECTED ]
        </td></tr>"""

    subject = (
        f"[{'⚠ FAIL' if status == 'FAIL' else '✓ PASS'}] "
        f"Compliance Scan — {account_name} / {framework.upper()} — Score {score:.1f}% (Grade {grade})"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{subject}</title>
</head>
<body style="margin:0;padding:0;background:#0b1120;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0b1120;padding:32px 0">
    <tr><td align="center">
      <table width="680" cellpadding="0" cellspacing="0" style="background:#131a2c;border-radius:12px;overflow:hidden;border:1px solid rgba(148,163,184,0.12)">

        <!-- ── Header ── -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);padding:28px 32px;border-bottom:1px solid rgba(59,130,246,0.3)">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div style="font-size:11px;color:#3b82f6;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px">
                    ◈ DIREWOLF · Cloud Compliance Platform
                  </div>
                  <div style="font-size:22px;font-weight:800;color:#f8fafc;line-height:1.2">
                    Compliance Scan Report
                  </div>
                  <div style="font-size:12px;color:#64748b;margin-top:6px;font-family:monospace">
                    {scan_time} UTC &nbsp;·&nbsp; Scan #{scan_id}
                  </div>
                </td>
                <td align="right" style="vertical-align:top">
                  <div style="background:{status_color}22;border:1px solid {status_color};border-radius:8px;padding:8px 18px;display:inline-block">
                    <div style="font-size:10px;color:{status_color};font-weight:700;letter-spacing:1px">{status}</div>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Score strip ── -->
        <tr>
          <td style="padding:0">
            <table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:1px solid rgba(148,163,184,0.08)">
              <tr>
                <td align="center" style="padding:32px;border-right:1px solid rgba(148,163,184,0.08)">
                  <div style="font-size:56px;font-weight:900;color:{sc_color};line-height:1;font-family:monospace">{score:.1f}%</div>
                  <div style="font-size:11px;color:#64748b;margin-top:6px;text-transform:uppercase;letter-spacing:1px">Compliance Score</div>
                  <div style="font-size:28px;font-weight:900;color:{sc_color};margin-top:4px">Grade {grade}</div>
                </td>
                <td style="padding:24px 32px;vertical-align:middle">
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="padding:6px 0">
                        <span style="color:#94a3b8;font-size:12px;font-family:monospace">Account &nbsp;&nbsp;&nbsp;</span>
                        <span style="color:#f8fafc;font-size:12px;font-weight:700;font-family:monospace">{account_name}</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:6px 0">
                        <span style="color:#94a3b8;font-size:12px;font-family:monospace">Provider &nbsp;&nbsp;</span>
                        <span style="color:#f8fafc;font-size:12px;font-weight:700;font-family:monospace">{provider.upper()}</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:6px 0">
                        <span style="color:#94a3b8;font-size:12px;font-family:monospace">Framework &nbsp;</span>
                        <span style="color:#f8fafc;font-size:12px;font-weight:700;font-family:monospace">{framework.upper()}</span>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Stat pills ── -->
        <tr>
          <td style="padding:24px 32px;border-bottom:1px solid rgba(148,163,184,0.08)">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                {''.join([
                    f'<td align="center" style="background:#1e293b;border-radius:8px;padding:16px;margin:0 4px">'
                    f'<div style="font-size:28px;font-weight:900;color:{clr};font-family:monospace">{val}</div>'
                    f'<div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px">{lbl}</div></td>'
                    for val, lbl, clr in [
                        (total_checks,   "Total Checks",  "#94a3b8"),
                        (passed_checks,  "Passed",        "#10b981"),
                        (failed_checks,  "Failed",        "#f59e0b"),
                        (critical_count, "Critical",      "#ef4444"),
                        (high_count,     "High",          "#f97316"),
                    ]
                ])}
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── Top failures table ── -->
        <tr>
          <td style="padding:24px 32px">
            <div style="font-size:13px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;font-family:monospace">
              ▸ Top Failing Checks
            </div>
            <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #1e293b;border-radius:8px;overflow:hidden">
              <thead>
                <tr style="background:#1e293b">
                  <th style="padding:10px 12px;text-align:left;font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:1px;font-weight:600">Policy</th>
                  <th style="padding:10px 12px;text-align:left;font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:1px;font-weight:600">Resource</th>
                  <th style="padding:10px 12px;text-align:center;font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:1px;font-weight:600">Severity</th>
                </tr>
              </thead>
              <tbody>
                {failures_rows}
                {no_failures_row}
              </tbody>
            </table>
          </td>
        </tr>

        <!-- ── Footer ── -->
        <tr>
          <td style="background:#0b1120;padding:20px 32px;border-top:1px solid rgba(148,163,184,0.08);text-align:center">
            <div style="font-size:11px;color:#374151;font-family:monospace">
              DIREWOLF Compliance Platform &nbsp;·&nbsp; Automated scan alert &nbsp;·&nbsp; Do not reply to this email
            </div>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    return subject, html


# ── SMTP dispatcher ──────────────────────────────────────────────────────────

async def dispatch_scan_alert(
    scan_id: int,
    account_name: str,
    provider: str,
    framework: str,
    score: float,
    total_checks: int,
    passed_checks: int,
    failed_checks: int,
    top_failures: list[dict],
) -> None:
    """
    Build and send the compliance scan result email.
    Reads SMTP config from settings. Silently skips if SMTP is unconfigured.
    Counts critical/high from top_failures list.
    """
    from app.config import get_settings
    settings = get_settings()

    if not settings.smtp_host or not settings.smtp_user:
        logger.info("SMTP not configured — skipping scan alert email")
        return

    critical_count = sum(1 for f in top_failures if (f.get("severity") or "").lower() == "critical")
    high_count     = sum(1 for f in top_failures if (f.get("severity") or "").lower() == "high")

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    to_email = settings.smtp_user          # send to the configured SMTP account holder
    subject, html = build_scan_email_html(
        account_name=account_name,
        provider=provider,
        framework=framework,
        score=score,
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        critical_count=critical_count,
        high_count=high_count,
        top_failures=top_failures,
        scan_id=scan_id,
        scan_time=scan_time,
    )

    smtp_pass = settings.smtp_password.get_secret_value() if settings.smtp_password else ""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = settings.smtp_from_email
        msg["To"]      = to_email
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
            smtp.starttls()
            smtp.login(settings.smtp_user, smtp_pass)
            smtp.send_message(msg)

        logger.info("Scan alert email sent", scan_id=scan_id, to=to_email, score=score)
    except Exception as exc:
        logger.error("Failed to send scan alert email", scan_id=scan_id, error=str(exc))
