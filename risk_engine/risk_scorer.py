from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import gmail_config
    ABUSEIPDB_API_KEY = getattr(gmail_config, 'ABUSEIPDB_API_KEY', '')
except (ImportError, AttributeError):
    ABUSEIPDB_API_KEY = ''


@dataclass
class RiskResult:
    risk_score: float
    risk_level: str
    access_decision: str


class DynamicRiskScorer:
    """Calculates dynamic access risk and policy action for ZTNA decisions."""

    LOW_CUTOFF = 35.0
    HIGH_CUTOFF = 70.0

    # Rebalanced weights — total sums to 1.0
    WEIGHTS = {
        "device_posture":       0.20,
        "ip_reputation":        0.15,
        "traffic_behavior":     0.15,
        "login_time":           0.10,
        "login_location":       0.10,
        "geo_vpn":              0.15,
        "failed_logins":        0.10,
        "behavior_pattern":     0.05,
    }

    # IP Reputation Cache: {ip_address: {"score": score, "timestamp": timestamp}}
    _ip_reputation_cache: dict[str, dict[str, Any]] = {}
    _CACHE_TTL = 300  # 5 minutes in seconds

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _clamp_0_100(self, value: float) -> float:
        return max(0.0, min(100.0, float(value)))

    def _parse_hour(self, login_time: Any) -> int:
        """Accepts hour as int, datetime, or HH:MM / HH:MM:SS string."""
        if isinstance(login_time, datetime):
            return login_time.hour
        if isinstance(login_time, int):
            if 0 <= login_time <= 23:
                return login_time
            raise ValueError("login_time integer must be in range 0-23")
        if isinstance(login_time, str):
            text = login_time.strip()
            for fmt in ("%H:%M", "%H:%M:%S"):
                try:
                    return datetime.strptime(text, fmt).hour
                except ValueError:
                    continue
            raise ValueError("login_time string must be HH:MM or HH:MM:SS")
        raise TypeError("login_time must be int, datetime, or HH:MM string")

    # ------------------------------------------------------------------
    # Original risk components
    # ------------------------------------------------------------------

    def _login_time_risk(self, login_time: Any) -> float:
        """Odd hours (22:00-05:59) are treated as high risk."""
        hour = self._parse_hour(login_time)
        if hour >= 22 or hour < 6:
            return 100.0
        return 20.0

    def _login_location_risk(self, login_location: str) -> float:
        normalized = (login_location or "").strip().lower()
        low_risk_terms  = {"known", "trusted", "familiar", "usual", "home", "office"}
        high_risk_terms = {"unknown", "new", "untrusted", "suspicious"}
        if normalized in low_risk_terms:
            return 15.0
        if normalized in high_risk_terms:
            return 100.0
        return 60.0

    @classmethod
    def set_thresholds(cls, low_cutoff: float, high_cutoff: float) -> None:
        low_value = max(0.0, min(100.0, float(low_cutoff)))
        high_value = max(low_value + 1.0, min(100.0, float(high_cutoff)))
        cls.LOW_CUTOFF = low_value
        cls.HIGH_CUTOFF = high_value

    @classmethod
    def reset_thresholds(cls) -> None:
        cls.LOW_CUTOFF = 35.0
        cls.HIGH_CUTOFF = 70.0

    @classmethod
    def get_thresholds(cls) -> dict[str, float]:
        return {
            "low_cutoff": float(cls.LOW_CUTOFF),
            "high_cutoff": float(cls.HIGH_CUTOFF),
        }

    def _risk_level(self, risk_score: float) -> str:
        if risk_score < self.LOW_CUTOFF:
            return "LOW"
        if risk_score < self.HIGH_CUTOFF:
            return "MEDIUM"
        return "HIGH"

    def _access_decision(self, risk_level: str) -> str:
        mapping = {"LOW": "full", "MEDIUM": "extra MFA", "HIGH": "blocked"}
        return mapping[risk_level]

    # ------------------------------------------------------------------
    # IP Reputation from AbuseIPDB with Caching
    # ------------------------------------------------------------------

    def get_ip_reputation_score(self, ip: str, sessions_log_path: str | None = None) -> dict[str, Any]:
        """
        Get IP reputation score from AbuseIPDB API with 5-minute caching.

        Returns: {"score": 0-100, "detail": str, "is_cached": bool, "abuseipdb_score": int}
        
        Falls back to 20.0 if API fails or key is missing.
        Logs fallback to sessions_log.json if provided.
        """
        default_score = 20.0
        default = {
            "score": default_score,
            "detail": "Default score (no API key or cached)",
            "is_cached": False,
            "abuseipdb_score": 0,
        }

        # Skip for private/LAN IPs
        if ip.startswith(("192.168.", "10.", "172.", "127.", "localhost")):
            return {
                "score": 5.0,
                "detail": "Private IP — neutral",
                "is_cached": False,
                "abuseipdb_score": 0,
            }

        # Check cache
        if ip in self._ip_reputation_cache:
            cached = self._ip_reputation_cache[ip]
            age = (datetime.now(timezone.utc) - cached["timestamp"]).total_seconds()
            if age < self._CACHE_TTL:
                return {
                    "score": cached["score"],
                    "detail": f"Cached (age: {int(age)}s)",
                    "is_cached": True,
                    "abuseipdb_score": cached["abuseipdb_score"],
                }

        # If no API key, return default and log fallback
        if not ABUSEIPDB_API_KEY or not ABUSEIPDB_API_KEY.strip():
            if sessions_log_path:
                self._log_ip_reputation_fallback(
                    ip=ip,
                    reason="No AbuseIPDB API key configured",
                    sessions_log_path=sessions_log_path,
                )
            return default

        if not _REQUESTS_AVAILABLE:
            if sessions_log_path:
                self._log_ip_reputation_fallback(
                    ip=ip,
                    reason="requests library not available",
                    sessions_log_path=sessions_log_path,
                )
            return default

        # Call AbuseIPDB API
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
        }

        try:
            resp = _requests.get(url, headers=headers, params=params, timeout=5)
            data = resp.json()

            if "data" not in data:
                reason = f"Invalid API response: {data.get('error', 'Unknown error')}"
                if sessions_log_path:
                    self._log_ip_reputation_fallback(ip, reason, sessions_log_path)
                return default

            abuse_score = data["data"].get("abuseConfidenceScore", 0)
            
            # Map AbuseIPDB score (0-100) to our risk formula
            # 0-5: low (5), 6-25: medium (40), 26-75: high (75), 76-100: critical (100)
            if abuse_score <= 5:
                risk_score = 5.0
                detail = f"Clean (AbuseIPDB: {abuse_score}%)"
            elif abuse_score <= 25:
                risk_score = 40.0
                detail = f"Low risk (AbuseIPDB: {abuse_score}%)"
            elif abuse_score <= 75:
                risk_score = 75.0
                detail = f"High risk (AbuseIPDB: {abuse_score}%)"
            else:
                risk_score = 100.0
                detail = f"Critical risk (AbuseIPDB: {abuse_score}%)"

            # Cache the result
            self._ip_reputation_cache[ip] = {
                "score": risk_score,
                "abuseipdb_score": abuse_score,
                "timestamp": datetime.now(timezone.utc),
            }

            return {
                "score": risk_score,
                "detail": detail,
                "is_cached": False,
                "abuseipdb_score": abuse_score,
            }

        except _requests.exceptions.Timeout:
            reason = "AbuseIPDB API timeout"
            if sessions_log_path:
                self._log_ip_reputation_fallback(ip, reason, sessions_log_path)
            return default

        except _requests.exceptions.ConnectionError:
            reason = "AbuseIPDB API connection error"
            if sessions_log_path:
                self._log_ip_reputation_fallback(ip, reason, sessions_log_path)
            return default

        except Exception as e:
            reason = f"AbuseIPDB API error: {type(e).__name__}: {str(e)}"
            if sessions_log_path:
                self._log_ip_reputation_fallback(ip, reason, sessions_log_path)
            return default

    def _log_ip_reputation_fallback(self, ip: str, reason: str, sessions_log_path: str) -> None:
        """Log IP reputation fallback event to sessions_log.json."""
        try:
            path = Path(sessions_log_path)
            if not path.exists():
                return

            data = json.loads(path.read_text(encoding="utf-8"))
            if "__ip_reputation_fallbacks" not in data:
                data["__ip_reputation_fallbacks"] = []

            data["__ip_reputation_fallbacks"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": ip,
                "reason": reason,
                "fallback_score": 20.0,
            })

            # Keep only last 100 fallback logs
            data["__ip_reputation_fallbacks"] = data["__ip_reputation_fallbacks"][-100:]

            path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass  # Silent fail — don't raise exceptions during logging

    # ------------------------------------------------------------------
    # Original risk components
    # ------------------------------------------------------------------

    def get_geo_vpn_risk(self, ip: str = "", home_country: str = "Pakistan") -> dict[str, Any]:
        """
        Call ip-api.com to detect VPN, proxy, hosting, or Tor exit nodes.
        Returns a risk score (0-100) and a breakdown dict.

        Score rules:
          - Tor detected        → 100 (immediate block)
          - Proxy or hosting    → 70  (suspicious)
          - Foreign country     → 50  (flagged)
          - Clean / home        → 5   (trusted)
        """
        default = {
            "risk_score": 5.0,
            "country": "Unknown",
            "city": "Unknown",
            "is_tor": False,
            "is_proxy": False,
            "is_hosting": False,
            "foreign_country": False,
            "detail": "API unavailable or skipped",
        }

        if not _REQUESTS_AVAILABLE:
            default["detail"] = "requests library not installed"
            return default

        target_ip = ip if ip and ip not in ("127.0.0.1", "localhost", "") else ""

        # Strip private/LAN IP ranges — let the API auto-detect public IP instead
        if target_ip.startswith(("192.168.", "10.", "172.")):
            target_ip = ""

        url = f"http://ip-api.com/json/{target_ip}?fields=country,city,proxy,hosting,tor"

        try:
            resp = _requests.get(url, timeout=5)
            data = resp.json()
        except Exception as exc:
            default["detail"] = f"API error: {exc}"
            return default

        country  = data.get("country", "Unknown")
        city     = data.get("city", "Unknown")
        is_tor   = bool(data.get("tor", False))
        is_proxy = bool(data.get("proxy", False))
        is_host  = bool(data.get("hosting", False))

        # If country is still Unknown (API couldn't resolve) → treat as neutral, not foreign
        if country in ("Unknown", "", None):
            return {
                "risk_score": 5.0,
                "country": "Unknown",
                "city": "Unknown",
                "is_tor": False,
                "is_proxy": False,
                "is_hosting": False,
                "foreign_country": False,
                "detail": "Location unresolvable — treated as neutral",
            }

        foreign  = country.strip().lower() != home_country.strip().lower()

        if is_tor:
            score = 100.0
            detail = "TOR EXIT NODE DETECTED — block"
        elif is_proxy or is_host:
            score = 70.0
            detail = f"VPN/Proxy/Hosting detected ({country}, {city})"
        elif foreign:
            score = 50.0
            detail = f"Foreign country: {country}, {city}"
        else:
            score = 5.0
            detail = f"Clean — {country}, {city}"

        return {
            "risk_score": score,
            "country": country,
            "city": city,
            "is_tor": is_tor,
            "is_proxy": is_proxy,
            "is_hosting": is_host,
            "foreign_country": foreign,
            "detail": detail,
        }

    # ------------------------------------------------------------------
    # NEW: Failed login attempts check (reads sessions_log.json)
    # ------------------------------------------------------------------

    def get_failed_login_risk(
        self,
        username: str,
        log_file: str = "sessions_log.json",
    ) -> dict[str, Any]:
        """
        Count failed/blocked sessions for this user in the last 24 hours.

        Risk tiers:
          0-2 failures  →  0  (normal)
          3-5 failures  →  50 (medium risk)
          5+ failures   →  100 (high risk — likely brute force)
        """
        default = {"risk_score": 0.0, "failure_count": 0, "detail": "No history"}

        path = Path(log_file)
        if not path.exists():
            return default

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        failure_count = 0

        for session_id, session in data.items():
            if str(session_id).startswith("__") or not isinstance(session, dict):
                continue
            if session.get("username", "").lower() != username.lower():
                continue
            if session.get("status") not in ("blocked", "failed"):
                continue
            try:
                login_dt = datetime.fromisoformat(session.get("login_time", ""))
                if login_dt.tzinfo is None:
                    login_dt = login_dt.replace(tzinfo=timezone.utc)
                if login_dt >= cutoff:
                    failure_count += 1
            except (ValueError, TypeError):
                continue

        if failure_count >= 5:
            score = 100.0
            detail = f"{failure_count} failures in 24h — HIGH risk (brute force)"
        elif failure_count >= 3:
            score = 50.0
            detail = f"{failure_count} failures in 24h — MEDIUM risk"
        else:
            score = 0.0
            detail = f"{failure_count} failures in 24h — normal"

        return {"risk_score": score, "failure_count": failure_count, "detail": detail}

    # ------------------------------------------------------------------
    # NEW: Login-time behavior vs historical pattern
    # ------------------------------------------------------------------

    def get_behavior_pattern_risk(
        self,
        username: str,
        current_hour: int,
        log_file: str = "sessions_log.json",
    ) -> dict[str, Any]:
        """
        Compare current login hour against the user's historical login window.

        If no history → neutral (0 risk).
        If outside normal window → 70 risk.
        If inside normal window → 0 risk.
        """
        default = {"risk_score": 0.0, "detail": "No login history — neutral"}

        path = Path(log_file)
        if not path.exists():
            return default

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

        hours = []
        for session_id, session in data.items():
            if str(session_id).startswith("__") or not isinstance(session, dict):
                continue
            if session.get("username", "").lower() != username.lower():
                continue
            if session.get("status") == "blocked":
                continue
            try:
                login_dt = datetime.fromisoformat(session.get("login_time", ""))
                hours.append(login_dt.hour)
            except (ValueError, TypeError):
                continue

        if len(hours) < 3:
            return default  # Not enough history — neutral

        min_hour = min(hours)
        max_hour = max(hours)
        # Allow ±1 hour tolerance
        in_range = (min_hour - 1) <= current_hour <= (max_hour + 1)

        if in_range:
            return {
                "risk_score": 0.0,
                "detail": f"Login hour {current_hour}h is within normal range ({min_hour}-{max_hour}h)",
            }
        else:
            return {
                "risk_score": 70.0,
                "detail": f"Login hour {current_hour}h is OUTSIDE normal range ({min_hour}-{max_hour}h)",
            }

    # ------------------------------------------------------------------
    # Main calculate_risk — updated with 3 new inputs
    # ------------------------------------------------------------------

    def calculate_risk(
        self,
        posture_score: float,
        login_location: str,
        login_time: Any,
        ip_reputation: float,
        traffic_behavior_score: float,
        # NEW optional inputs (safe defaults so old callers still work)
        geo_vpn_score: float = 5.0,
        failed_login_score: float = 0.0,
        behavior_pattern_score: float = 0.0,
    ) -> dict[str, Any]:
        """
        Calculate total risk (0-100, higher is riskier) from weighted inputs.
        """
        posture_risk  = 100.0 - self._clamp_0_100(posture_score)
        ip_risk       = self._clamp_0_100(ip_reputation)
        traffic_risk  = self._clamp_0_100(traffic_behavior_score)
        time_risk     = self._login_time_risk(login_time)
        location_risk = self._login_location_risk(login_location)
        geo_risk      = self._clamp_0_100(geo_vpn_score)
        failed_risk   = self._clamp_0_100(failed_login_score)
        behavior_risk = self._clamp_0_100(behavior_pattern_score)

        weighted_score = (
            posture_risk   * self.WEIGHTS["device_posture"]
            + ip_risk      * self.WEIGHTS["ip_reputation"]
            + traffic_risk * self.WEIGHTS["traffic_behavior"]
            + time_risk    * self.WEIGHTS["login_time"]
            + location_risk * self.WEIGHTS["login_location"]
            + geo_risk     * self.WEIGHTS["geo_vpn"]
            + failed_risk  * self.WEIGHTS["failed_logins"]
            + behavior_risk * self.WEIGHTS["behavior_pattern"]
        )

        risk_score = round(self._clamp_0_100(weighted_score), 2)
        # Ensure very small baseline risk to avoid zero scores which can be misleading.
        if risk_score < 1.0:
            risk_score = 1.0
        risk_level = self._risk_level(risk_score)
        decision   = self._access_decision(risk_level)

        result = RiskResult(risk_score=risk_score, risk_level=risk_level, access_decision=decision)

        return {
            "inputs": {
                "posture_score":          posture_score,
                "login_location":         login_location,
                "login_time":             str(login_time),
                "ip_reputation":          ip_reputation,
                "traffic_behavior_score": traffic_behavior_score,
                "geo_vpn_score":          geo_vpn_score,
                "failed_login_score":     failed_login_score,
                "behavior_pattern_score": behavior_pattern_score,
            },
            "component_risk": {
                "posture_risk":    round(posture_risk, 2),
                "ip_risk":         round(ip_risk, 2),
                "traffic_risk":    round(traffic_risk, 2),
                "time_risk":       round(time_risk, 2),
                "location_risk":   round(location_risk, 2),
                "geo_risk":        round(geo_risk, 2),
                "failed_risk":     round(failed_risk, 2),
                "behavior_risk":   round(behavior_risk, 2),
            },
            "risk_score":  result.risk_score,
            "risk_level":  result.risk_level,
            "access":      result.access_decision,
        }

    def recalculate_runtime_risk(
        self,
        username: str,
        ip: str,
        posture_score: float,
        traffic_behavior_score: float,
        sessions_log_path: str,
        login_location: str = "known",
        login_time: Any | None = None,
        home_country: str = "Pakistan",
    ) -> dict[str, Any]:
        """
        Build a fresh runtime risk snapshot for active-session monitoring.
        NOW uses AbuseIPDB API for real IP reputation scoring instead of hardcoded 20.0.
        """
        eval_time = login_time if login_time is not None else datetime.now().strftime("%H:%M:%S")
        current_hour = datetime.now().hour

        # Get real IP reputation from AbuseIPDB (with caching and fallback)
        ip_rep_result = self.get_ip_reputation_score(ip=ip, sessions_log_path=sessions_log_path)
        ip_reputation = ip_rep_result.get("score", 20.0)

        geo_result = self.get_geo_vpn_risk(ip=ip, home_country=home_country)
        failed_result = self.get_failed_login_risk(username=username, log_file=sessions_log_path)
        behavior_result = self.get_behavior_pattern_risk(
            username=username,
            current_hour=current_hour,
            log_file=sessions_log_path,
        )

        risk_result = self.calculate_risk(
            posture_score=posture_score,
            login_location=login_location,
            login_time=eval_time,
            ip_reputation=ip_reputation,
            traffic_behavior_score=traffic_behavior_score,
            geo_vpn_score=float(geo_result.get("risk_score", 5.0)),
            failed_login_score=float(failed_result.get("risk_score", 0.0)),
            behavior_pattern_score=float(behavior_result.get("risk_score", 0.0)),
        )

        return {
            "risk": risk_result,
            "ip_reputation": ip_rep_result,
            "geo_vpn": geo_result,
            "failed_logins": failed_result,
            "behavior_pattern": behavior_result,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }


if __name__ == "__main__":
    scorer = DynamicRiskScorer()

    # Test geo/VPN check
    geo = scorer.get_geo_vpn_risk()

    # Test full risk calculation
    sample = scorer.calculate_risk(
        posture_score=82,
        login_location="unknown",
        login_time="23:45",
        ip_reputation=68,
        traffic_behavior_score=71,
        geo_vpn_score=geo["risk_score"],
        failed_login_score=50.0,
        behavior_pattern_score=70.0,
    )
    import json as _json
