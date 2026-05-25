"""
ZTNA (Zero Trust Network Access) Framework
Policy Decision Point (PDP)
"""

import random
import datetime


def calculate_risk_score(posture_score, ip_reputation=None, login_hour=None):
    """
    Calculate dynamic risk score based on multiple factors.
    
    Formula:
    risk = (100 - posture_score) * 0.40
         + ip_reputation * 0.35
         + (25 if login_hour < 6 or login_hour > 22 else 0) * 0.25
    
    Args:
        posture_score: 0-100 from device check
        ip_reputation: 0-100 (if None, random)
        login_hour: current hour 0-23 (if None, use current)
    
    Returns: risk score 0-100
    """
    if ip_reputation is None:
        ip_reputation = random.randint(0, 100)
    
    if login_hour is None:
        login_hour = datetime.datetime.now().hour

    suspicious_hour = 25 if (login_hour < 6 or login_hour > 22) else 0

    risk = (
        (100 - posture_score) * 0.40 +
        ip_reputation * 0.35 +
        suspicious_hour * 0.25
    )

    return min(100, max(0, int(risk)))


def get_risk_level(score):
    """
    Categorize risk score into levels.
    - 0-40: LOW
    - 41-70: MEDIUM
    - 71-100: HIGH
    
    Returns: "LOW", "MEDIUM", or "HIGH"
    """
    if score <= 40:
        return "LOW"
    elif score <= 70:
        return "MEDIUM"
    else:
        return "HIGH"


def check_rbac(role, app):
    """
    Check if a role has access to an application.
    
    Role definitions:
    - admin: app1, app2, app3, admin_panel, reports
    - analyst: app1, app2, reports, dashboard
    - viewer: app1, dashboard
    
    Args:
        role: "admin", "analyst", or "viewer"
        app: application name
    
    Returns: True if access allowed, False otherwise
    """
    role_permissions = {
        "admin": ["app1", "app2", "app3", "admin_panel", "reports"],
        "analyst": ["app1", "app2", "reports", "dashboard"],
        "viewer": ["app1", "dashboard"]
    }

    return app in role_permissions.get(role, [])