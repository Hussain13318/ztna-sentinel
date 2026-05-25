from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

try:
    from filelock import FileLock
    FILELOCK_AVAILABLE = True
except ImportError:
    FILELOCK_AVAILABLE = False


class SessionManager:
    """Manages user sessions, event logs, persistence, and replay."""

    def __init__(self, log_file: str = "sessions_log.json") -> None:
        self.log_file = Path(log_file)
        self.sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load_existing_log()

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _load_existing_log(self) -> None:
        if not self.log_file.exists():
            return

        if FILELOCK_AVAILABLE:
            lock = FileLock(str(self.log_file) + ".lock", timeout=5)
            try:
                with lock:
                    try:
                        data = json.loads(self.log_file.read_text(encoding="utf-8"))
                        if isinstance(data, dict):
                            self.sessions = data
                    except (json.JSONDecodeError, OSError):
                        self.sessions = {}
            except Exception as e:
                print(f"Warning: File lock timeout or error on sessions_log.json read: {e}")
                # Fallback: try without lock
                try:
                    data = json.loads(self.log_file.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        self.sessions = data
                except (json.JSONDecodeError, OSError):
                    self.sessions = {}
        else:
            try:
                data = json.loads(self.log_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.sessions = data
            except (json.JSONDecodeError, OSError):
                self.sessions = {}

    def _save_to_file(self) -> None:
        # Stamp last writer metadata so multi-process debugging is easier
        try:
            import os
            self.sessions["__last_writer"] = {
                "pid": os.getpid(),
                "cwd": os.getcwd(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            pass
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, indent=2, default=str)
        except Exception as err:
            print(f"Error saving sessions_log.json: {err}")

    def reload_from_disk(self) -> None:
        """Reload JSON from disk (multi-instance / concurrent viewers)."""
        with self._lock:
            self._load_existing_log()
            # Diagnostic: if file was last written by a different process, record an audit entry
            try:
                import os
                lw = self.sessions.get("__last_writer")
                if isinstance(lw, dict):
                    last_pid = lw.get("pid")
                    last_cwd = lw.get("cwd")
                    if last_pid and int(last_pid) != os.getpid():
                        # Append diagnostic audit entry (do not call methods that re-save __last_writer)
                        if "__file_change_audit" not in self.sessions:
                            self.sessions["__file_change_audit"] = []
                        self.sessions["__file_change_audit"].append({
                            "timestamp": self._utc_now(),
                            "event": "external_write_detected",
                            "last_writer_pid": last_pid,
                            "last_writer_cwd": last_cwd,
                            "noted_by_pid": os.getpid(),
                        })
                        # Cap the diagnostic list
                        if len(self.sessions["__file_change_audit"]) > 500:
                            self.sessions["__file_change_audit"] = self.sessions["__file_change_audit"][-500:]
                        # Persist diagnostic note immediately
                        try:
                            self._save_to_file()
                        except Exception:
                            pass
            except Exception:
                pass

    def _ensure_meta_lists(self) -> None:
        if "__persistent_alerts" not in self.sessions:
            self.sessions["__persistent_alerts"] = []
        if "__soc_pending" not in self.sessions:
            self.sessions["__soc_pending"] = []
        if "__file_change_audit" not in self.sessions:
            self.sessions["__file_change_audit"] = []
        if "__portal_db" not in self.sessions:
            self.sessions["__portal_db"] = {
                "profiles": {},
                "messages": [],
                "library_holds": [],
                "fee_ledger": [],
                "registrar_snapshots": [],
            }
        if "__portal_db_audit" not in self.sessions:
            self.sessions["__portal_db_audit"] = []
        if "__blocked_ips" not in self.sessions:
            self.sessions["__blocked_ips"] = []
        if "__incident_reports" not in self.sessions:
            self.sessions["__incident_reports"] = []

    def persist_dashboard_alert(self, alert: dict[str, Any]) -> None:
        """Persist alert into sessions_log.json for shared SOC visibility."""
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            self.sessions["__persistent_alerts"].append(dict(alert))
            if len(self.sessions["__persistent_alerts"]) > 800:
                self.sessions["__persistent_alerts"] = self.sessions["__persistent_alerts"][-800:]
            self._save_to_file()

    def append_soc_pending(self, record: dict[str, Any]) -> None:
        """Queue SOC timed response for CRITICAL/HIGH student threats."""
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            self.sessions["__soc_pending"].append(dict(record))
            if len(self.sessions["__soc_pending"]) > 200:
                self.sessions["__soc_pending"] = self.sessions["__soc_pending"][-200:]
            self._save_to_file()

    def list_open_soc_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            return [r for r in self.sessions["__soc_pending"] if r.get("state") == "open"]

    def try_resolve_soc_pending(
        self,
        alert_id: str,
        soc_username: str,
        resolution: str,
        detail: str = "",
    ) -> dict[str, Any]:
        """
        First successful caller wins. resolution: block_student | dismiss | auto_timeout
        """
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            for rec in self.sessions["__soc_pending"]:
                if str(rec.get("id")) != str(alert_id):
                    continue
                if rec.get("state") != "open":
                    return {"ok": False, "record": rec, "reason": "already_resolved"}
                rec["state"] = "closed"
                rec["resolution"] = resolution
                rec["resolved_by"] = soc_username
                rec["resolved_at"] = self._utc_now()
                rec["resolution_detail"] = detail
                self._save_to_file()
                return {"ok": True, "record": rec, "reason": ""}
            return {"ok": False, "record": None, "reason": "not_found"}

    def log_file_change_audit(
        self,
        who: str,
        path: str,
        summary: str,
        severity_hint: str = "INFO",
    ) -> None:
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            self.sessions["__file_change_audit"].append({
                "timestamp": self._utc_now(),
                "who": who,
                "path": path,
                "summary": summary,
                "severity_hint": severity_hint,
            })
            if len(self.sessions["__file_change_audit"]) > 500:
                self.sessions["__file_change_audit"] = self.sessions["__file_change_audit"][-500:]
            self._save_to_file()

    def has_active_student_username(self, username: str) -> str | None:
        uname = username.strip().lower()
        with self._lock:
            self._load_existing_log()
            for sid, session in self.sessions.items():
                if str(sid).startswith("__") or not isinstance(session, dict):
                    continue
                if session.get("status") != "active":
                    continue
                if str(session.get("role", "")).lower() != "student":
                    continue
                if str(session.get("username", "")).lower() == uname:
                    return str(sid)
        return None

    def register_student_security_fields(
        self,
        session_id: str,
        session_token: str,
        registered_country: str,
        authorized_ip: str,
    ) -> bool:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session or not isinstance(session, dict):
                return False
            session["session_token"] = session_token
            session["session_cookie"] = session_token
            session["registered_country"] = registered_country or "Unknown"
            session["authorized_ip"] = authorized_ip
            session.setdefault("activity_feed", [])
            session.setdefault("action_timestamps", [])
            self._save_to_file()
        return True

    def verify_student_session_context(
        self,
        session_id: str,
        session_token: str,
        current_ip: str,
    ) -> dict[str, Any]:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session or not isinstance(session, dict):
                return {"ok": False, "reason": "missing_session", "hijack": False}
            if session.get("status") != "active":
                return {"ok": False, "reason": "not_active", "hijack": False}
            if str(session.get("session_token", "")) != str(session_token):
                return {"ok": False, "reason": "bad_token", "hijack": False}
            auth_ip = str(session.get("authorized_ip", ""))
            if auth_ip and current_ip != auth_ip:
                return {"ok": False, "reason": "ip_mismatch", "hijack": True}
            return {"ok": True, "reason": "", "hijack": False}

    def log_student_portal_action(
        self,
        session_id: str,
        action_type: str,
        details: dict[str, Any],
    ) -> bool:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session or not isinstance(session, dict):
                return False
            ts = self._utc_now()
            event = {
                "timestamp": ts,
                "event_type": "student_portal_action",
                "details": {"action_type": action_type, **details},
            }
            session.setdefault("events", []).append(event)
            feed = session.setdefault("activity_feed", [])
            feed.append({
                "timestamp": ts,
                "action_type": action_type,
                "summary": details.get("summary", action_type),
            })
            if len(feed) > 300:
                del feed[:-300]
            stamps = session.setdefault("action_timestamps", [])
            stamps.append(datetime.now(timezone.utc).timestamp())
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).timestamp()
            while stamps and stamps[0] < cutoff:
                stamps.pop(0)
            self._save_to_file()
        return True

    def student_action_rate_count(self, session_id: str) -> int:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session:
                return 0
            stamps = session.get("action_timestamps") or []
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=30)).timestamp()
            return len([t for t in stamps if t >= cutoff])

    def append_session_event(self, session_id: str, event_type: str, details: dict[str, Any]) -> bool:
        """Append a structured event to a session (thread-safe)."""
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session or not isinstance(session, dict):
                return False
            self._log_event(session_id, event_type, details)
            self._save_to_file()
            return True

    def patch_session(self, session_id: str, updates: dict[str, Any]) -> bool:
        """Merge updates into session record and persist."""
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session or not isinstance(session, dict):
                return False
            session.update(updates)
            self._save_to_file()
            return True

    def invalidate_session(self, session_id: str, reason: str) -> bool:
        sid = str(session_id or "").strip()
        if not sid:
            return False
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(sid)
            if not session:
                return False
            session["status"] = "blocked"
            session.setdefault("events", []).append({
                "timestamp": self._utc_now(),
                "event_type": "security_invalidation",
                "details": {"reason": reason},
            })
            self._save_to_file()
        return True

    # ------------------------------------------------------------------
    # Simulated portal database (persisted in sessions_log.json)
    # ------------------------------------------------------------------

    def find_active_session_id_for_user(self, username: str, role: str = "student") -> str | None:
        """Return active session id for username+role, if any."""
        uname = username.strip().lower()
        r = (role or "").strip().lower()
        with self._lock:
            self._load_existing_log()
            for sid, session in self.sessions.items():
                if str(sid).startswith("__") or not isinstance(session, dict):
                    continue
                if session.get("status") != "active":
                    continue
                if str(session.get("role", "")).lower() != r:
                    continue
                if str(session.get("username", "")).lower() == uname:
                    return str(sid)
        return None

    def get_portal_profile(self, username: str) -> dict[str, Any]:
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            k = username.strip().lower()
            base = dict(self.sessions["__portal_db"]["profiles"].get(k) or {})
        if "fee_balance" not in base:
            base["fee_balance"] = 12500.0
        base.setdefault("phone", "")
        base.setdefault("bio", "")
        return base

    def list_portal_messages_for_student(self, username: str) -> list[dict[str, Any]]:
        k = username.strip().lower()
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            rows: list[dict[str, Any]] = []
            for m in self.sessions["__portal_db"].get("messages") or []:
                if not isinstance(m, dict):
                    continue
                if str(m.get("from_user", "")).lower() == k or str(m.get("to_user", "")).lower() == k:
                    rows.append(dict(m))
        return rows[-80:]

    def list_portal_audit_for_username(self, username: str, limit: int = 12) -> list[dict[str, Any]]:
        k = username.strip().lower()
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            out: list[dict[str, Any]] = []
            for r in reversed(self.sessions.get("__portal_db_audit") or []):
                if not isinstance(r, dict):
                    continue
                tgt = str(r.get("target_username", "")).lower()
                ek = str(r.get("entity_key", "")).lower()
                actor = str(r.get("actor_username", "")).lower()
                if tgt == k or ek == k or (r.get("entity") == "portal_message" and actor == k):
                    out.append(dict(r))
                    if len(out) >= limit:
                        break
            return list(reversed(out))

    def portal_database_mutation(
        self,
        *,
        actor_role: str,
        actor_username: str,
        actor_session_id: str,
        operation: str,
        entity: str,
        entity_key: str,
        payload: dict[str, Any],
        target_username: str | None = None,
    ) -> dict[str, Any]:
        """Apply a simulated DB change, append authoritative audit row, persist."""
        tid = str(uuid.uuid4())
        tgt = (target_username or entity_key or "").strip().lower()
        audit: dict[str, Any] = {
            "id": tid,
            "timestamp": self._utc_now(),
            "actor_role": actor_role,
            "actor_username": actor_username,
            "actor_session_id": actor_session_id,
            "operation": operation,
            "entity": entity,
            "entity_key": str(entity_key),
            "target_username": tgt,
            "payload": dict(payload),
        }
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            db = self.sessions["__portal_db"]

            if entity == "portal_profile" and operation.upper() in {"UPSERT", "INSERT", "UPDATE"}:
                prof = db.setdefault("profiles", {})
                key = tgt or entity_key.strip().lower()
                slot = dict(prof.get(key) or {})
                for fld in ("phone", "bio"):
                    if fld in payload:
                        slot[fld] = str(payload.get(fld, ""))
                if "fee_balance" in payload:
                    try:
                        slot["fee_balance"] = float(payload["fee_balance"])
                    except (TypeError, ValueError):
                        pass
                prof[key] = slot

            elif entity == "portal_message" and operation.upper() == "INSERT":
                db.setdefault("messages", []).append(
                    {
                        "id": tid,
                        "from_user": str(payload.get("from_user", actor_username)),
                        "to_user": str(payload.get("to_user", "admin")),
                        "body": str(payload.get("body", "")),
                        "timestamp": self._utc_now(),
                    }
                )
                if len(db["messages"]) > 300:
                    db["messages"] = db["messages"][-300:]

            elif entity == "fee_payment" and operation.upper() == "INSERT":
                pay_user = tgt or entity_key.strip().lower()
                amt = float(payload.get("amount", 0) or 0)
                db.setdefault("fee_ledger", []).append(
                    {
                        "id": tid,
                        "username": pay_user,
                        "amount": amt,
                        "timestamp": self._utc_now(),
                    }
                )
                prof = db.setdefault("profiles", {})
                slot = dict(prof.get(pay_user) or {})
                bal = float(slot.get("fee_balance", 12500.0))
                slot["fee_balance"] = max(0.0, bal - amt)
                prof[pay_user] = slot
                if len(db["fee_ledger"]) > 400:
                    db["fee_ledger"] = db["fee_ledger"][-400:]

            elif entity == "library_hold" and operation.upper() == "INSERT":
                db.setdefault("library_holds", []).append(
                    {
                        "id": tid,
                        "username": tgt,
                        "book": str(payload.get("book", "")),
                        "timestamp": self._utc_now(),
                    }
                )
                if len(db["library_holds"]) > 400:
                    db["library_holds"] = db["library_holds"][-400:]

            elif entity == "registrar_override" and operation.upper() == "INSERT":
                db.setdefault("registrar_snapshots", []).append(
                    {
                        "id": tid,
                        "target_username": tgt,
                        "note": str(payload.get("note", "")),
                        "soc_operator": actor_username,
                        "timestamp": self._utc_now(),
                    }
                )
                if len(db["registrar_snapshots"]) > 200:
                    db["registrar_snapshots"] = db["registrar_snapshots"][-200:]

            self.sessions["__portal_db_audit"].append(audit)
            if len(self.sessions["__portal_db_audit"]) > 1500:
                self.sessions["__portal_db_audit"] = self.sessions["__portal_db_audit"][-1500:]
            self._save_to_file()
        return audit

    # ------------------------------------------------------------------
    # Account Lockout Management
    # ------------------------------------------------------------------

    def check_account_lockout(self, username: str) -> dict[str, Any]:
        with self._lock:
            self._load_existing_log()
            if "__account_lockouts" not in self.sessions:
                return {"is_locked": False, "remaining_seconds": 0, "reason": ""}

            lockout = self.sessions["__account_lockouts"].get(username.lower())
            if not lockout:
                return {"is_locked": False, "remaining_seconds": 0, "reason": ""}

            locked_until_str = lockout.get("locked_until")
            try:
                locked_until = datetime.fromisoformat(locked_until_str)
            except (ValueError, TypeError):
                return {"is_locked": False, "remaining_seconds": 0, "reason": ""}

            now = datetime.now(timezone.utc)
            if locked_until <= now:
                del self.sessions["__account_lockouts"][username.lower()]
                self._save_to_file()
                return {"is_locked": False, "remaining_seconds": 0, "reason": ""}

            remaining = (locked_until - now).total_seconds()
            return {
                "is_locked": True,
                "remaining_seconds": int(remaining),
                "reason": lockout.get("reason", "Too many failed login attempts"),
            }

    def lock_account(self, username: str, lock_duration_minutes: int = 15, reason: str = "Too many failed attempts") -> None:
        with self._lock:
            self._load_existing_log()
            if "__account_lockouts" not in self.sessions:
                self.sessions["__account_lockouts"] = {}

            locked_until = datetime.now(timezone.utc) + timedelta(minutes=lock_duration_minutes)
            self.sessions["__account_lockouts"][username.lower()] = {
                "username": username,
                "locked_at": self._utc_now(),
                "locked_until": locked_until.isoformat(),
                "reason": reason,
                "failure_count": 0,
            }
            self._save_to_file()

    # ------------------------------------------------------------------
    # IP Blacklist / Blocked IPs
    # ------------------------------------------------------------------

    def add_blocked_ip(self, ip: str, reason: str, blocked_by: str) -> None:
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            rec = {
                "ip": str(ip),
                "reason": str(reason),
                "blocked_by": str(blocked_by),
                "date_blocked": self._utc_now(),
            }
            self.sessions["__blocked_ips"].append(rec)
            # cap history
            if len(self.sessions["__blocked_ips"]) > 500:
                self.sessions["__blocked_ips"] = self.sessions["__blocked_ips"][-500:]
            self._save_to_file()

    def list_blocked_ips(self) -> list[dict[str, str]]:
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            return list(self.sessions.get("__blocked_ips", []))

    # ------------------------------------------------------------------
    # Incident reports (persisted for SOC review)
    # ------------------------------------------------------------------
    def add_incident_report(self, session_id: str, report_text: str, author: str) -> None:
        """Persist a generated incident report into sessions_log.json for SOC review."""
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            rec = {
                "id": str(uuid.uuid4()),
                "timestamp": self._utc_now(),
                "session_id": str(session_id),
                "author": str(author),
                "report": str(report_text),
            }
            self.sessions["__incident_reports"].append(rec)
            if len(self.sessions["__incident_reports"]) > 500:
                self.sessions["__incident_reports"] = self.sessions["__incident_reports"][-500:]
            self._save_to_file()

    def list_incident_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            self._load_existing_log()
            self._ensure_meta_lists()
            rows = list(reversed(self.sessions.get("__incident_reports", [])[-limit:]))
            return rows

    def list_recent_activity(self, limit: int = 60) -> list[dict[str, Any]]:
        """Aggregate recent activity_feed entries across sessions into a single sorted list."""
        with self._lock:
            self._load_existing_log()
            out: list[dict[str, Any]] = []
            for sid, session in self.sessions.items():
                if not isinstance(session, dict) or str(sid).startswith("__"):
                    continue
                feed = session.get("activity_feed") or []
                for entry in feed:
                    if not isinstance(entry, dict):
                        continue
                    row = dict(entry)
                    row.setdefault("session_id", str(sid))
                    row.setdefault("username", session.get("username", ""))
                    out.append(row)
            # Sort by timestamp desc (attempt iso parse fallback)
            def _ts_key(r: dict[str, Any]) -> float:
                try:
                    return datetime.fromisoformat(str(r.get("timestamp"))).timestamp()
                except Exception:
                    try:
                        return float(r.get("timestamp", 0))
                    except Exception:
                        return 0.0

            out.sort(key=_ts_key, reverse=True)
            return out[:limit]

    def unlock_account(self, username: str) -> bool:
        with self._lock:
            self._load_existing_log()
            if "__account_lockouts" in self.sessions and username.lower() in self.sessions["__account_lockouts"]:
                del self.sessions["__account_lockouts"][username.lower()]
                self._save_to_file()
                return True
            return False

    # ------------------------------------------------------------------
    # Login Attempt Logging
    # ------------------------------------------------------------------

    def log_login_attempt(
        self,
        username: str,
        ip: str,
        device_info: str = "",
        success: bool = False,
        reason: str = "",
    ) -> None:
        with self._lock:
            self._load_existing_log()
            if "__login_attempts" not in self.sessions:
                self.sessions["__login_attempts"] = []

            attempt = {
                "timestamp": self._utc_now(),
                "username": username,
                "ip": ip,
                "device": device_info,
                "success": bool(success),
                "reason": reason,
            }

            self.sessions["__login_attempts"].append(attempt)

            if len(self.sessions["__login_attempts"]) > 1000:
                self.sessions["__login_attempts"] = self.sessions["__login_attempts"][-1000:]

            self._save_to_file()

    # ------------------------------------------------------------------
    # Failed Login Tracking for Account Lockout
    # ------------------------------------------------------------------

    def increment_failed_logins(self, username: str, ip: str, reason: str = "") -> int:
        with self._lock:
            self._load_existing_log()
            if "__failed_logins" not in self.sessions:
                self.sessions["__failed_logins"] = {}

            username_lower = username.lower()
            if username_lower not in self.sessions["__failed_logins"]:
                self.sessions["__failed_logins"][username_lower] = {
                    "count": 0,
                    "first_attempt": self._utc_now(),
                    "last_ip": ip,
                    "last_attempt": self._utc_now(),
                }

            record = self.sessions["__failed_logins"][username_lower]
            record["count"] += 1
            record["last_ip"] = ip
            record["last_attempt"] = self._utc_now()

            self._save_to_file()
            return int(record["count"])

    def reset_failed_logins(self, username: str) -> None:
        with self._lock:
            self._load_existing_log()
            if "__failed_logins" in self.sessions and username.lower() in self.sessions["__failed_logins"]:
                del self.sessions["__failed_logins"][username.lower()]
                self._save_to_file()

    def get_failed_login_count(self, username: str) -> int:
        with self._lock:
            self._load_existing_log()
            if "__failed_logins" not in self.sessions:
                return 0
            record = self.sessions["__failed_logins"].get(username.lower())
            return int(record.get("count", 0)) if record else 0

    # ------------------------------------------------------------------
    # Suspicious Login Detection (Different IP than last 3 logins)
    # ------------------------------------------------------------------

    def get_last_successful_logins(self, username: str, count: int = 3) -> list[dict[str, Any]]:
        with self._lock:
            self._load_existing_log()
            logins = []
            for session_id, session in self.sessions.items():
                if str(session_id).startswith("__") or not isinstance(session, dict):
                    continue
                if session.get("username", "").lower() != username.lower():
                    continue
                if session.get("status") not in ("active", "ended"):
                    continue
                try:
                    login_time = datetime.fromisoformat(session.get("login_time", ""))
                    logins.append({
                        "ip": session.get("ip", ""),
                        "login_time": login_time.isoformat(),
                        "device": session.get("device_info", ""),
                    })
                except ValueError:
                    continue

            logins.sort(key=lambda x: x["login_time"], reverse=True)
            return logins[:count]

    def is_suspicious_login(self, username: str, current_ip: str) -> dict[str, Any]:
        last_logins = self.get_last_successful_logins(username, count=3)

        if not last_logins:
            return {"is_suspicious": False, "reason": "No login history", "previous_ips": []}

        previous_ips = [login["ip"] for login in last_logins]

        if current_ip not in previous_ips:
            return {
                "is_suspicious": True,
                "reason": f"Login from new IP: {current_ip} (previous: {', '.join(previous_ips)})",
                "previous_ips": previous_ips,
            }

        return {
            "is_suspicious": False,
            "reason": "Login IP matches recent history",
            "previous_ips": previous_ips,
        }

    def _log_event(self, session_id: str, event_type: str, details: dict[str, Any]) -> None:
        event = {
            "timestamp": self._utc_now(),
            "event_type": event_type,
            "details": details,
        }
        self.sessions[session_id]["events"].append(event)

    def create_session(
        self,
        username: str,
        role: str,
        ip: str,
        risk_score: float,
        accessed_apps: list[str] | None = None,
        status: str = "active",
        session_id: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._load_existing_log()
            sid = session_id or str(uuid.uuid4())
            login_time = self._utc_now()

            session_record: dict[str, Any] = {
                "session_id": sid,
                "username": username,
                "role": role,
                "ip": ip,
                "login_time": login_time,
                "risk_score": float(risk_score),
                "accessed_apps": accessed_apps or [],
                "status": status,
                "events": [],
                "activity_feed": [],
                "action_timestamps": [],
            }
            if extra_fields:
                session_record.update(extra_fields)

            self.sessions[sid] = session_record
            self._log_event(
                sid,
                "login",
                {
                    "username": username,
                    "role": role,
                    "ip": ip,
                    "risk_score": float(risk_score),
                },
            )
            self._save_to_file()
            return session_record

    def update_risk_score(self, session_id: str, new_risk_score: float) -> bool:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session:
                return False

            old_score = float(session.get("risk_score", 0))
            session["risk_score"] = float(new_risk_score)
            self._log_event(
                session_id,
                "risk_change",
                {"old_risk_score": old_score, "new_risk_score": float(new_risk_score)},
            )
            self._save_to_file()
            return True

    def log_app_access(self, session_id: str, app_name: str) -> bool:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session:
                return False

            if app_name not in session["accessed_apps"]:
                session["accessed_apps"].append(app_name)

            self._log_event(session_id, "app_access", {"application": app_name})
            self._save_to_file()
            return True

    def log_alert(self, session_id: str, alert_message: str, severity: str = "medium") -> bool:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session:
                return False

            self._log_event(
                session_id,
                "alert",
                {"severity": severity, "message": alert_message},
            )
            self._save_to_file()
            return True

    def end_session(self, session_id: str, status: str = "ended") -> bool:
        if status not in {"active", "blocked", "ended"}:
            status = "ended"

        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session:
                return False

            session["status"] = status
            self._log_event(session_id, "logout", {"final_status": status})
            self._save_to_file()
            return True

    def replay_session(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self._load_existing_log()
            session = self.sessions.get(session_id)
            if not session:
                return []

            return list(session.get("events", []))

    def list_recent_activity(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent student portal activity across all sessions, newest first."""
        with self._lock:
            self._load_existing_log()
            out: list[dict[str, Any]] = []
            for sid, session in self.sessions.items():
                if str(sid).startswith("__") or not isinstance(session, dict):
                    continue
                feed = session.get("activity_feed") or []
                for entry in feed:
                    if isinstance(entry, dict):
                        rec = dict(entry)
                        rec.setdefault("session_id", sid)
                        rec.setdefault("username", session.get("username", ""))
                        out.append(rec)

            # Sort by timestamp desc if possible
            def _ts_key(x: dict[str, Any]) -> float:
                try:
                    from datetime import datetime
                    return float(datetime.fromisoformat(str(x.get("timestamp"))).timestamp())
                except Exception:
                    return 0.0

            out.sort(key=_ts_key, reverse=True)
            return out[:limit]


if __name__ == "__main__":
    manager = SessionManager()

    session = manager.create_session(
        username="alice",
        role="analyst",
        ip="203.0.113.11",
        risk_score=42.0,
        accessed_apps=["app1"],
    )
    sid = session["session_id"]

    manager.log_app_access(sid, "reports")
    manager.update_risk_score(sid, 63.5)
    manager.log_alert(sid, "Traffic anomaly detected", severity="high")
    manager.end_session(sid, status="ended")

    print(manager.replay_session(sid))
