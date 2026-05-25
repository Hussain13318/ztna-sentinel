"""Flask dashboard for the ZTNA framework (modular version)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json

from flask import Flask, redirect, render_template, url_for


ROOT_DIR = Path(__file__).resolve().parent.parent
SESSIONS_FILE = ROOT_DIR / "sessions_log.json"
ALERTS_FILE = ROOT_DIR / "alerts_log.txt"

app = Flask(__name__)


def _load_sessions() -> list[dict]:
	if not SESSIONS_FILE.exists():
		return []
	try:
		data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
		# Handle both dict (with session IDs as keys) and list formats
		if isinstance(data, dict):
			return list(data.values())
		return data
	except Exception:
		return []


def _save_sessions(sessions: list[dict]) -> None:
	SESSIONS_FILE.write_text(json.dumps(sessions, indent=2), encoding="utf-8")


def _load_alerts() -> list[str]:
	if not ALERTS_FILE.exists():
		return []
	return [line.strip() for line in ALERTS_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]


def _append_alert(message: str) -> None:
	with ALERTS_FILE.open("a", encoding="utf-8") as f:
		f.write(message + "\n")


@app.route("/")
def index():
	sessions = _load_sessions()
	alerts = _load_alerts()
	active_count = len([s for s in sessions if s.get("status", "").lower() == "active"])
	blocked_count = len([s for s in sessions if s.get("status", "").lower() == "blocked"])

	return render_template(
		"index.html",
		sessions=sessions,
		alerts=alerts,
		active_count=active_count,
		blocked_count=blocked_count,
		total_count=len(sessions),
	)


@app.route("/sessions")
def sessions_view():
	sessions = _load_sessions()
	return render_template(
		"index.html",
		sessions=sessions,
		alerts=_load_alerts(),
		active_count=len([s for s in sessions if s.get("status", "").lower() == "active"]),
		blocked_count=len([s for s in sessions if s.get("status", "").lower() == "blocked"]),
		total_count=len(sessions),
	)


@app.route("/block/<session_id>")
def block_session(session_id: str):
	sessions = _load_sessions()
	updated = False
	for session in sessions:
		if session.get("session_id") == session_id:
			session["status"] = "blocked"
			session.setdefault("events", []).append(
				{"event": "BLOCKED", "timestamp": datetime.now().isoformat()}
			)
			updated = True
			break

	if updated:
		_save_sessions(sessions)
		_append_alert(
			f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SESSION BLOCKED from dashboard: {session_id}"
		)

	return redirect(url_for("index"))


if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000, debug=True)
