"""
ZTNA (Zero Trust Network Access) Framework
Policy Enforcement Point (PEP)
"""

import json
import datetime
import os
import sys


def create_session(username, role, ip, risk_score, risk_level, sessions_list):
    """
    Create a new session and add to global sessions list.
    
    Args:
        username: user identifier
        role: user role (admin, analyst, viewer)
        ip: source IP address
        risk_score: calculated risk (0-100)
        risk_level: risk category (LOW, MEDIUM, HIGH)
    
    Returns: session dict
    """
    session_id = f"S{len(sessions_list) + 1:03d}"

    session = {
        "session_id": session_id,
        "username": username,
        "role": role,
        "ip": ip,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status": "ACTIVE",
        "login_time": datetime.datetime.now().isoformat(),
        "logout_time": None,
        "events": []
    }
    
    sessions_list.append(session)
    return session


def block_session(session_id, sessions, alerts):
    """
    Block a session by ID.
    Updates session status to BLOCKED and logs alert.
    
    Args:
        session_id: ID of session to block
    
    Returns: True if blocked, False if not found
    """
    for session in sessions:
        if session["session_id"] == session_id:
            session["status"] = "BLOCKED"
            session["events"].append({
                "event": "BLOCKED",
                "timestamp": datetime.datetime.now().isoformat()
            })
            
            alert = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            alert += f"SESSION BLOCKED: {session_id} | User: {session['username']} | IP: {session['ip']}"
            alerts.append(alert)
            
            return True
    
    return False


def end_session(session_id, sessions):
    """
    End a session by ID.
    Sets status to ENDED and records logout time.
    
    Args:
        session_id: ID of session to end
    
    Returns: True if ended, False if not found
    """
    for session in sessions:
        if session["session_id"] == session_id:
            session["status"] = "ENDED"
            session["logout_time"] = datetime.datetime.now().isoformat()
            session["events"].append({
                "event": "LOGOUT",
                "timestamp": datetime.datetime.now().isoformat()
            })
            return True
    
    return False


def save_sessions_log(sessions):
    """
    Save all sessions to sessions_log.json.
    """
    try:
        if hasattr(sys, '_MEIPASS'):
            filepath = os.path.join(sys._MEIPASS, "sessions_log.json")
        else:
            filepath = os.path.join(os.path.abspath("."), "sessions_log.json")
        with open(filepath, 'w') as f:
            json.dump(sessions, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving sessions log: {e}")
        return False