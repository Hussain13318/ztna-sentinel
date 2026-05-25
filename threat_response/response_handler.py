from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable


# Shared alerts sink for dashboard consumption.
ALERTS: list[dict[str, Any]] = []

# Optional hook: persist alert dict to sessions_log.json (set by GUI).
_ALERT_PERSIST_HOOK: Callable[[dict[str, Any]], None] | None = None


def register_alert_persist_hook(fn: Callable[[dict[str, Any]], None] | None) -> None:
    """Register callback invoked after each dashboard alert (e.g. write to JSON)."""
    global _ALERT_PERSIST_HOOK
    _ALERT_PERSIST_HOOK = fn


# Alert severity levels
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#c53030",  # Dark red
    "HIGH": "#f44336",      # Red
    "MEDIUM": "#d69e2e",    # Warning yellow
    "LOW": "#0288d1",       # Blue
    "INFO": "#2f855a",      # Green
}


class ThreatResponseHandler:
    """Applies automated response actions based on risk and anomaly signals."""

    def __init__(self) -> None:
        self.blocklist: dict[str, dict[str, Any]] = {}
        self.terminated_sessions: dict[str, dict[str, Any]] = {}
        self.response_log: list[dict[str, Any]] = []

    def _utc_timestamp(self) -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def _log_action(
        self,
        session_id: str,
        action: str,
        reason: str,
        risk_level: str,
        is_anomalous: bool,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        entry = {
            "timestamp": self._utc_timestamp(),
            "session_id": session_id,
            "risk_level": risk_level,
            "is_anomalous": is_anomalous,
            "action": action,
            "reason": reason,
            "ip_address": ip_address,
        }
        self.response_log.append(entry)
        return entry

    def send_alert_to_dashboard(
        self,
        message: str,
        severity: str = "INFO",
        acknowledged: bool = False,
        acknowledged_by: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Push an alert event to in-memory ALERTS and optional JSON persistence."""
        severity = severity.upper() if severity else "INFO"
        if severity not in SEVERITY_LEVELS:
            severity = "INFO"

        alert: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "timestamp": self._utc_timestamp(),
            "severity": severity,
            "message": message,
            "acknowledged": bool(acknowledged),
            "acknowledged_by": acknowledged_by,
            "acknowledged_at": None,
        }
        if extra:
            alert.update(extra)
        # Deduplicate identical alerts recently to avoid noisy repeats
        try:
            recent = ALERTS[-12:]
            duplicate = False
            for a in reversed(recent):
                if a.get("message") == alert.get("message") and a.get("severity") == alert.get("severity"):
                    # If identical alert in last few items, skip adding to reduce noise
                    duplicate = True
                    break
            if not duplicate:
                ALERTS.append(alert)
        except Exception:
            ALERTS.append(alert)
        if _ALERT_PERSIST_HOOK is not None:
            try:
                _ALERT_PERSIST_HOOK(dict(alert))
            except Exception:
                pass
        return alert

    def block_ip(self, ip_address: str, reason: str) -> dict[str, Any]:
        """Add IP to blocklist dictionary and emit alert."""
        entry = {
            "blocked_at": self._utc_timestamp(),
            "reason": reason,
        }
        self.blocklist[ip_address] = entry
        self.send_alert_to_dashboard(
            message=f"IP {ip_address} blocked. Reason: {reason}",
            severity="high",
        )
        return entry

    def terminate_session(self, session_id: str, reason: str) -> dict[str, Any]:
        """Terminate and record session state by session_id."""
        entry = {
            "terminated_at": self._utc_timestamp(),
            "reason": reason,
            "status": "terminated",
        }
        self.terminated_sessions[session_id] = entry
        self.send_alert_to_dashboard(
            message=f"Session {session_id} terminated. Reason: {reason}",
            severity="critical",
        )
        return entry

    def decide_and_respond(
        self,
        session_id: str,
        risk_level: str,
        is_anomalous: bool,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """
        Apply response policy:
        - LOW risk + no anomaly => allow session
        - MEDIUM risk or anomaly => extra MFA challenge
        - HIGH risk or anomalous => terminate session immediately

        Priority:
        1) HIGH or anomalous => terminate
        2) MEDIUM => challenge
        3) LOW + no anomaly => allow
        """
        normalized_risk = (risk_level or "").strip().upper()

        if normalized_risk == "HIGH" or is_anomalous:
            reason = "High risk or anomaly detected"
            self.terminate_session(session_id=session_id, reason=reason)
            if ip_address:
                self.block_ip(ip_address=ip_address, reason=reason)

            log_entry = self._log_action(
                session_id=session_id,
                action="terminate",
                reason=reason,
                risk_level=normalized_risk,
                is_anomalous=is_anomalous,
                ip_address=ip_address,
            )
            return {
                "session_id": session_id,
                "action": "terminate",
                "status": "blocked",
                "log": log_entry,
            }

        if normalized_risk == "MEDIUM":
            reason = "Medium risk - extra MFA required"
            self.send_alert_to_dashboard(
                message=f"Session {session_id} challenged with extra MFA.",
                severity="medium",
            )
            log_entry = self._log_action(
                session_id=session_id,
                action="extra_mfa",
                reason=reason,
                risk_level=normalized_risk,
                is_anomalous=is_anomalous,
                ip_address=ip_address,
            )
            return {
                "session_id": session_id,
                "action": "extra_mfa",
                "status": "challenge",
                "log": log_entry,
            }

        reason = "Low risk and no anomaly"
        self.send_alert_to_dashboard(
            message=f"Session {session_id} allowed.",
            severity="info",
        )
        log_entry = self._log_action(
            session_id=session_id,
            action="allow",
            reason=reason,
            risk_level=normalized_risk,
            is_anomalous=is_anomalous,
            ip_address=ip_address,
        )
        return {
            "session_id": session_id,
            "action": "allow",
            "status": "active",
            "log": log_entry,
        }


if __name__ == "__main__":
    handler = ThreatResponseHandler()

    print(handler.decide_and_respond("sess-100", "LOW", False, "203.0.113.5"))
    print(handler.decide_and_respond("sess-101", "MEDIUM", False, "203.0.113.6"))
    print(handler.decide_and_respond("sess-102", "HIGH", True, "203.0.113.7"))

    print("Alerts:", ALERTS)
