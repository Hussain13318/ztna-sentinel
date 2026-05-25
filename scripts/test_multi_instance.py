"""
Simple multi-instance simulator for sessions_log.json.
Run this from the repository root with: python scripts/test_multi_instance.py
It will spawn two processes: writer and reader. The writer will create a session and append an activity entry;
the reader will reload the file and print recent activity aggregated via SessionManager.list_recent_activity().
"""
import time
import multiprocessing as mp
import sys
from pathlib import Path
import uuid

REPO_ROOT = Path(__file__).resolve().parent.parent
SESSIONS_FILE = REPO_ROOT / "sessions_log.json"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def writer_process():
    from session_manager.session_manager import SessionManager
    sm = SessionManager(log_file=str(SESSIONS_FILE))
    print("Writer: creating session...")
    sid = str(uuid.uuid4())
    sm.create_session(username="sim_user", role="student", ip="127.0.0.1", risk_score=5.0, session_id=sid)
    sm.log_student_portal_action(sid, "sim_action", {"summary": "writer action"})
    print("Writer: wrote session and action. Sleeping then exiting...")
    time.sleep(2)


def reader_process():
    from session_manager.session_manager import SessionManager
    sm = SessionManager(log_file=str(SESSIONS_FILE))
    print("Reader: waiting briefly then reloading from disk...")
    time.sleep(1)
    sm.reload_from_disk()
    active = [
        sid for sid, session in sm.sessions.items()
        if not str(sid).startswith("__") and isinstance(session, dict) and session.get("status") == "active"
    ]
    print("Reader: active sessions:", active)
    print("Reader: sessions keys:", list(sm.sessions.keys())[:10])
    print("Reader: last writer:", sm.sessions.get("__last_writer"))
    print("Reader: file change audit entries:", len(sm.sessions.get("__file_change_audit", [])) if isinstance(sm.sessions.get("__file_change_audit"), list) else 0)
    rows = sm.list_recent_activity(limit=10)
    print("Reader: recent activity rows:")
    for r in rows:
        print(r)


if __name__ == "__main__":
    p_writer = mp.Process(target=writer_process)
    p_reader = mp.Process(target=reader_process)
    p_writer.start()
    p_reader.start()
    p_writer.join()
    p_reader.join()
    print("Simulation finished. Check sessions_log.json and __file_change_audit for diagnostic entries.")
