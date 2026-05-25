from __future__ import annotations

import csv
import hashlib
import json
import re
import socket
import sys
import threading
import time
import secrets
import uuid
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

import biometric_auth

try:
    import winsound
    WINSOUND_AVAILABLE = True
except ImportError:
    WINSOUND_AVAILABLE = False

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anomaly_detection.anomaly_detector import SessionAnomalyDetector
from device_posture.posture_checker import DevicePostureChecker
from logout import LogoutHandler
from mfa.mfa_handler import MFAHandler
from rbac.rbac_manager import RBACManager
from risk_engine.risk_scorer import DynamicRiskScorer
from session_manager.session_manager import SessionManager
from threat_response.response_handler import ALERTS, ThreatResponseHandler, register_alert_persist_hook
from traffic_monitor.traffic_capture import TrafficMonitor

try:
    import gmail_config
    GMAIL_EMAIL = gmail_config.SENDER_EMAIL
    GMAIL_PASSWORD = gmail_config.SENDER_APP_PASSWORD
except ImportError:
    GMAIL_EMAIL = None
    GMAIL_PASSWORD = None


class ZTNAApp:
    """Main ZTNA Framework GUI Application."""

    PROTECTED_APPS = [
        ("alerts_dashboard", "Alerts Dashboard", "🚨"),
        ("traffic_log_viewer", "Traffic Log Viewer", "📡"),
        ("threat_report_generator", "Threat Report Generator", "🧾"),
        ("session_management_console", "Session Management Console", "🧑‍💻"),
        ("ip_blacklist_manager", "IP Blacklist Manager", "🚫"),
        ("policy_control_panel", "Policy Control Panel", "⚙️"),
        ("audit_log_exporter", "Audit Log Exporter", "📤"),
    ]

    # Light theme colors
    BG_DARK = "#f7f4ee"
    BG_MEDIUM = "#ffffff"
    FG_WHITE = "#222222"
    ACCENT_BLUE = "#c58a1f"
    SUCCESS_GREEN = "#2f855a"
    WARNING_YELLOW = "#d69e2e"
    DANGER_RED = "#c53030"
    
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("ZTNA Sentinel - Root Kit Rebels")
        self.root.geometry("1100x700")
        self.root.configure(bg=self.BG_DARK)
        
        # Initialize modules
        self.base_dir = Path(__file__).resolve().parent.parent
        self.sessions_log = self.base_dir / "sessions_log.json"
        self.student_accounts_file = self.base_dir / "student_accounts.json"
        self.student_accounts: dict[str, dict[str, Any]] = self._load_student_accounts()
        
        self.mfa_handler = MFAHandler(GMAIL_EMAIL, GMAIL_PASSWORD)
        self.posture_checker = DevicePostureChecker()
        self.risk_scorer = DynamicRiskScorer()
        self.rbac_manager = RBACManager()
        self.traffic_monitor = TrafficMonitor()
        self.anomaly_detector = SessionAnomalyDetector()
        self.threat_handler = ThreatResponseHandler()
        self.session_manager = SessionManager(log_file=str(self.sessions_log))
        register_alert_persist_hook(self.session_manager.persist_dashboard_alert)
        self.logout_handler = LogoutHandler(timeout_seconds=600, logout_callback=self._process_logout)

        # Concurrent student dashboards: session_id -> state
        self.student_dashboards: dict[str, dict[str, Any]] = {}
        self._soc_alert_timers: dict[str, threading.Timer] = {}
        self._soc_shown_alert_ids: set[str] = set()
        self._soc_timers_started: set[str] = set()
        self._soc_popup_windows: dict[str, tk.Toplevel] = {}
        self._expect_sessions_log_mutation = False
        self._expect_student_accounts_mutation = False
        self._last_sessions_log_hash: str | None = None
        self._last_student_accounts_hash: str | None = None
        # SOC alert timeout (seconds) before auto-timeout
        self.SOC_ALERT_TIMEOUT = 30.0
        
        # Current session state
        self.current_session_id: str | None = None
        self.current_username: str = ""
        self.current_email: str = ""
        self.current_role: str = ""
        self.current_ip: str = ""
        self.monitoring_active = False
        self.login_time_risk_score: float = 0.0
        self.risk_spike_alert_active = False
        self.last_runtime_risk_level: str = "LOW"
        self.step_up_in_progress = False
        self.current_tooltip_window: tk.Toplevel | None = None
        self.student_portal_window: tk.Toplevel | None = None
        self.student_login_window: tk.Toplevel | None = None
        self.student_signup_window: tk.Toplevel | None = None
        self.student_dashboard_window: tk.Toplevel | None = None  # legacy single-window ref (last opened)
        self.current_session_detail_text: str = ""
        self.student_otp_secret_key: str | None = None
        self._latest_geo_result: dict[str, Any] = {}
        self._personal_status_after_id: str | None = None
        
        # Background threads
        self.monitor_thread: threading.Thread | None = None
        self.stop_monitoring = threading.Event()
        self.risk_recalc_thread: threading.Thread | None = None
        self.stop_risk_recalc = threading.Event()
        
        # Apply dark theme styling
        self._configure_styles()
        
        # Create main notebook (tabs) but HIDDEN until entry point is selected
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.notebook.pack_forget()  # Hide initially
        
        # Create all tabs
        self.login_tab = self._create_login_tab()
        self.personal_status_tab = self._create_personal_security_status_tab()
        self.sessions_tab = self._create_sessions_tab()
        self.alerts_tab = self._create_alerts_tab()
        self.traffic_tab = self._create_traffic_tab()
        self.history_tab = self._create_history_tab()
        self.incident_reports_tab = self._create_incident_reports_tab()
        self.ip_blacklist_tab = self._create_ip_blacklist_manager_tab()
        self.policy_sim_tab = self._create_policy_simulation_tab()
        self.protected_resources_tab = self._create_protected_resources_tab()
        self.risk_threshold_tab = self._create_risk_threshold_editor_tab()
        self.device_registry_tab = self._create_device_registry_tab()
        self.audit_export_tab = self._create_audit_log_export_tab()
        self.system_health_tab = self._create_system_health_tab()
        self.activity_heatmap_tab = self._create_activity_heatmap_tab()

        self.role_tabs = {
            "personal_dashboard": self.login_tab,
            "personal_security_status": self.personal_status_tab,
            "alerts": self.alerts_tab,
            "active_sessions": self.sessions_tab,
            "traffic_monitor": self.traffic_tab,
            "session_history": self.history_tab,
            "incident_reports": self.incident_reports_tab,
            "ip_blacklist_manager": self.ip_blacklist_tab,
            "policy_simulation": self.policy_sim_tab,
            "protected_resources": self.protected_resources_tab,
            "risk_threshold_editor": self.risk_threshold_tab,
            "device_registry": self.device_registry_tab,
            "audit_export": self.audit_export_tab,
            "system_health": self.system_health_tab,
            "activity_heatmap": self.activity_heatmap_tab,
        }

        self.apply_role_restrictions("guest")

        self.notebook.select(self.login_tab)

        self._prime_file_integrity_baseline()
        threading.Thread(target=self._file_integrity_loop, daemon=True).start()
        self.root.after(5000, self._poll_soc_alerts_loop)
        
        # Start auto-refresh loops
        self._start_auto_refresh()
        
        # SHOW ENTRY POINT POPUP ON APP LAUNCH
        self.root.after(100, self._show_entry_point_popup)
        # Ensure app close cleans up active sessions
        try:
            self.root.protocol("WM_DELETE_WINDOW", self._on_app_close)
        except Exception:
            pass
    
    def _configure_styles(self) -> None:
        """Configure ttk styles for light theme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure Notebook
        style.configure("TNotebook", background=self.BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.BG_MEDIUM, 
                       foreground=self.FG_WHITE, padding=[20, 10])
        style.map("TNotebook.Tab", background=[("selected", self.ACCENT_BLUE)])
        
        # Configure Frames
        style.configure("TFrame", background=self.BG_DARK)
        style.configure("Dark.TFrame", background=self.BG_MEDIUM)
        
        # Configure Labels
        style.configure("TLabel", background=self.BG_DARK, 
                       foreground=self.FG_WHITE, font=("Arial", 10))
        style.configure("Title.TLabel", font=("Arial", 14, "bold"))
        style.configure("Success.TLabel", foreground=self.SUCCESS_GREEN, 
                       font=("Arial", 11, "bold"))
        style.configure("Warning.TLabel", foreground=self.WARNING_YELLOW, 
                       font=("Arial", 11, "bold"))
        style.configure("Danger.TLabel", foreground=self.DANGER_RED, 
                       font=("Arial", 11, "bold"))
        
        # Configure Buttons
        style.configure("TButton", background=self.ACCENT_BLUE, 
                       foreground=self.FG_WHITE, borderwidth=0, 
                       font=("Arial", 10, "bold"), padding=10)
        style.map("TButton", background=[("active", "#a66f17")])
        
        # Configure Entry
        style.configure("TEntry", fieldbackground=self.BG_MEDIUM, 
                       foreground=self.FG_WHITE, borderwidth=2)
        
        # Configure Combobox
        style.configure("TCombobox", fieldbackground=self.BG_MEDIUM, 
                       foreground=self.FG_WHITE, arrowcolor=self.FG_WHITE)
        
        # Configure Treeview
        style.configure("Treeview", background=self.BG_MEDIUM, 
                       foreground=self.FG_WHITE, fieldbackground=self.BG_MEDIUM,
                       borderwidth=0)
        style.configure("Treeview.Heading", background=self.ACCENT_BLUE, 
                       foreground=self.FG_WHITE, font=("Arial", 10, "bold"))
        style.map("Treeview", background=[("selected", self.ACCENT_BLUE)])
    
    def _show_entry_point_popup(self) -> None:
        """Show entry point selector popup at app startup."""
        popup = tk.Toplevel(self.root)
        popup.title("ZTNA Sentinel - Root Kit Rebels")
        popup.geometry("500x300")
        popup.configure(bg="#1a1a2e")
        popup.resizable(False, False)
        popup.transient(self.root)
        
        # Prevent closing with X button
        popup.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Make popup modal - blocks interaction with main window
        popup.grab_set()
        
        # Center on screen
        popup.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.root.winfo_screenheight() // 2) - (300 // 2)
        popup.geometry(f"500x300+{x}+{y}")
        
        # Main frame
        main_frame = tk.Frame(popup, bg="#1a1a2e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Shield icon and title
        header_frame = tk.Frame(main_frame, bg="#1a1a2e")
        header_frame.pack(fill=tk.X, pady=(0, 16))
        
        shield_canvas = tk.Canvas(header_frame, width=40, height=40, bg="#1a1a2e", highlightthickness=0)
        shield_canvas.pack(side=tk.LEFT, padx=(0, 12))
        shield_canvas.create_polygon([5, 4, 35, 4, 35, 20, 20, 32, 5, 20], fill="#FFB300", outline="#FFB300", width=2)
        
        title_frame = tk.Frame(main_frame, bg="#1a1a2e")
        title_frame.pack(fill=tk.X, pady=(0, 6))
        tk.Label(title_frame, text="ZTNA Sentinel", bg="#1a1a2e", fg="#ffffff", font=("Arial", 18, "bold")).pack(anchor="w")
        
        # Subtitle
        tk.Label(main_frame, text="Select your access portal", bg="#1a1a2e", fg="#888888", font=("Arial", 12)).pack(anchor="w", pady=(0, 18))
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg="#1a1a2e")
        buttons_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        
        def on_blue_team_click():
            popup.destroy()
            self._handle_portal_selection("blue_team")
        
        def on_student_click():
            popup.destroy()
            self._handle_portal_selection("student")
        
        # Blue Team button
        blue_btn = tk.Button(
            buttons_frame,
            text="🔒 BLUE TEAM\nAuthorized Personnel Only",
            bg="#003366",
            fg="#00FFFF",
            font=("Arial", 11, "bold"),
            bd=2,
            relief="raised",
            command=on_blue_team_click,
            padx=20,
            pady=20,
            width=20,
            height=3
        )
        blue_btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=0)
        
        # Student Portal button
        student_btn = tk.Button(
            buttons_frame,
            text="🎓 STUDENT PORTAL\nAir University Students",
            bg="#1a4a1a",
            fg="#00FF00",
            font=("Arial", 11, "bold"),
            bd=2,
            relief="raised",
            command=on_student_click,
            padx=20,
            pady=20,
            width=20,
            height=3
        )
        student_btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=0)
        
        # Footer
        tk.Label(main_frame, text="Developed by Team Root Kit Rebels", bg="#1a1a2e", fg="#666666", font=("Arial", 8, "italic")).pack(anchor="w")
        
        popup.focus_force()
        self.root.wait_window(popup)
    
    def _handle_portal_selection(self, portal_type: str) -> None:
        """Handle portal selection from entry point popup."""
        # Show the notebook now that user has made a choice
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        if portal_type == "blue_team":
            # Show blue team login (main window)
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
            self.notebook.select(self.login_tab)
        elif portal_type == "student":
            # Show student portal in isolated window
            self._open_student_portal_landing()
    

    def _get_local_ip(self) -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    
    # ================== TAB 1: LOGIN PANEL ==================
    
    def _create_login_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg="#ffffff")
        self.notebook.add(tab, text="🏠 Personal Dashboard")

        outer = tk.Frame(tab, bg="#ffffff")
        outer.pack(fill=tk.BOTH, expand=True, padx=28, pady=18)

        header_frame = tk.Frame(outer, bg="#ffffff", height=80)
        header_frame.pack(fill=tk.X, pady=(0, 12))
        header_frame.pack_propagate(False)

        shield_canvas = tk.Canvas(header_frame, width=60, height=60, bg="#ffffff", highlightthickness=0)
        shield_canvas.pack(side=tk.LEFT, padx=(0, 12))
        shield_canvas.create_polygon([10, 8, 50, 8, 50, 35, 30, 55, 10, 35], fill="#c58a1f", outline="#000000", width=2)
        shield_canvas.create_line([20, 35, 25, 42, 38, 22], fill="#ffffff", width=3)

        branding_frame = tk.Frame(header_frame, bg="#ffffff")
        branding_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(branding_frame, text="ZTNA Sentinel", bg="#ffffff", fg="#222222", font=("Arial", 34, "bold")).pack(anchor="w", pady=(0, 2))
        tk.Label(branding_frame, text="Root Kit Rebels - Zero Trust Network Access", bg="#ffffff", fg="#555555", font=("Arial", 14, "italic")).pack(anchor="w")

        self.login_datetime_label = tk.Label(header_frame, text="", bg="#ffffff", fg="#666666", font=("Arial", 10))
        self.login_datetime_label.pack(side=tk.RIGHT, anchor="ne")
        self._update_login_datetime()

        layout = tk.Frame(outer, bg="#ffffff")
        layout.pack(fill=tk.BOTH, expand=True)
        layout.columnconfigure(0, weight=1)
        layout.columnconfigure(1, weight=1)

        left_panel = tk.Frame(layout, bg="#ffffff", padx=10, pady=10)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        right_panel = tk.Frame(layout, bg="#ffffff", padx=10, pady=10)
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        tk.Label(left_panel, text="Hi User, hope you are having a good day.", bg="#ffffff", fg="#222222", font=("Arial", 20, "italic")).pack(anchor="w", pady=(0, 6))
        tk.Label(left_panel, text="Log in as:", bg="#ffffff", fg="#222222", font=("Arial", 18, "italic")).pack(anchor="w", pady=(0, 14))

        ROLE_CARDS = [
            ("soc_operator", "SOC Operator", "#FFB300", "#000000", "👁️"),
            ("threat_analyst", "Threat Analyst", "#4CAF50", "#000000", "🔍"),
            ("security_engineer", "Security Engineer", "#F44336", "#000000", "🛡️"),
        ]

        self.selected_role_var = tk.StringVar(value="soc_operator")
        role_cards: list[tk.Frame] = []
        cards_row = tk.Frame(left_panel, bg="#ffffff")
        cards_row.pack(pady=(0, 18), anchor="w")

        def make_card(parent, role_value: str, label: str, bg_color: str, text_color: str, icon: str, on_click=None):
            card = tk.Frame(parent, bg=bg_color, width=170, height=122, bd=4, relief="raised", cursor="hand2")
            card.pack(side=tk.LEFT, padx=12)
            card.pack_propagate(False)
            tk.Label(card, text=icon, bg=bg_color, font=("Arial", 24)).pack(pady=(15, 2))
            tk.Label(card, text=label, bg=bg_color, fg=text_color, font=("Arial", 13, "bold")).pack()

            def select(event=None, current_card=card, current_role=role_value):
                self.selected_role_var.set(current_role)
                for other_card in role_cards:
                    other_card.config(relief="raised", bd=4)
                current_card.config(relief="solid", bd=6)

            for widget in [card, *card.winfo_children()]:
                widget.bind("<Button-1>", select)
            return card

        for role_value, label, bg_color, text_color, icon in ROLE_CARDS:
            role_cards.append(make_card(cards_row, role_value, label, bg_color, text_color, icon))
        role_cards[0].config(relief="solid", bd=6)

        form_frame = tk.Frame(left_panel, bg="#ffffff")
        form_frame.pack(fill=tk.X, pady=(8, 0))

        def lbl(text, row):
            tk.Label(form_frame, text=text, bg="#ffffff", fg="#222222", font=("Arial", 11)).grid(row=row, column=0, sticky="e", padx=12, pady=8)

        lbl("Username:", 0)
        self.username_entry = tk.Entry(form_frame, width=28, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.username_entry.grid(row=0, column=1, padx=12, pady=8)

        lbl("Email:", 1)
        self.email_entry = tk.Entry(form_frame, width=28, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.email_entry.grid(row=1, column=1, padx=12, pady=8)

        lbl("Password:", 2)
        password_row = tk.Frame(form_frame, bg="#ffffff")
        password_row.grid(row=2, column=1, padx=12, pady=8, sticky="ew")
        self.password_entry = tk.Entry(password_row, width=22, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.password_show_var = tk.BooleanVar(value=False)
        self.password_toggle_btn = tk.Checkbutton(password_row, text="Show", variable=self.password_show_var, bg="#ffffff", font=("Arial", 9), command=self._toggle_password_visibility, relief="flat", activebackground="#ffffff")
        self.password_toggle_btn.pack(side=tk.LEFT)

        self.role_combo = ttk.Combobox(form_frame, width=1, values=["soc_operator", "threat_analyst", "security_engineer"], state="readonly", textvariable=self.selected_role_var)
        self.role_combo.grid(row=3, column=1, padx=0, pady=0)
        self.role_combo.grid_remove()

        self.login_btn = tk.Button(form_frame, text="Login", bg="#FFB300", fg="#000000", font=("Arial", 11, "bold"), relief="flat", cursor="hand2", command=self._handle_login, activebackground="#d28f00")
        self.login_btn.grid(row=4, column=0, columnspan=2, pady=(16, 12))

        self.otp_frame = tk.Frame(form_frame, bg="#ffffff")
        self.otp_frame.grid(row=5, column=0, columnspan=2, pady=5)
        self.otp_frame.grid_remove()
        tk.Label(self.otp_frame, text="Enter OTP:", bg="#ffffff", font=("Arial", 10)).grid(row=0, column=0, padx=8)
        self.otp_entry = tk.Entry(self.otp_frame, width=18, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.otp_entry.grid(row=0, column=1, padx=8)
        self.verify_otp_btn = tk.Button(self.otp_frame, text="Verify OTP", bg="#2f855a", fg="#ffffff", font=("Arial", 10, "bold"), relief="flat", cursor="hand2", command=self._handle_otp_verification)
        self.verify_otp_btn.grid(row=0, column=2, padx=8)

        self.mfa_status_label = tk.Label(form_frame, text="", bg="#ffffff", font=("Arial", 10))
        self.mfa_status_label.grid(row=6, column=0, columnspan=2, pady=5)

        self.posture_frame = tk.LabelFrame(right_panel, text="Device Posture", bg="#ffffff", fg="#222222", font=("Arial", 11, "bold"), padx=12, pady=12)
        self.posture_frame.pack(fill=tk.BOTH, expand=True)
        self.posture_text = tk.Text(self.posture_frame, height=18, width=54, bg="#fbfaf7", fg="#222222", font=("Courier", 9), state="disabled", relief="solid", bd=1, wrap="word")
        self.posture_text.pack(fill=tk.BOTH, expand=True)
        self._set_posture_placeholder()

        self.risk_label = tk.Label(right_panel, text="", bg="#ffffff", fg="#222222", font=("Arial", 15, "bold"))
        self.risk_label.pack(pady=(14, 6), anchor="w")

        self.live_risk_badge = tk.Label(right_panel, text="Live Risk: --", bg=self.SUCCESS_GREEN, fg="#ffffff", font=("Arial", 11, "bold"), padx=10, pady=4, relief="solid", bd=1)
        self.live_risk_badge.pack(pady=(0, 10), anchor="w")

        self.logout_btn = tk.Button(right_panel, text="Log Out", bg="#c53030", fg="#ffffff", font=("Arial", 10, "bold"), relief="flat", cursor="hand2", command=lambda: self._process_logout(is_automatic=False))
        self.logout_btn.pack(pady=(8, 0), anchor="w")
        self.logout_btn.pack_forget()

        footer = tk.Label(outer, text="Developed by Team Root Kit Rebels", bg="#ffffff", fg="#666666", font=("Arial", 10, "italic"))
        footer.pack(side=tk.BOTTOM, pady=(16, 0))

        return tab


    def _toggle_password_visibility(self) -> None:
        """Toggle password field visibility (mask/unmask)."""
        if self.password_show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def _update_login_datetime(self) -> None:
        """Update login screen date/time display every second."""
        try:
            now = datetime.now()
            formatted = now.strftime("%A, %B %d, %Y\n%I:%M:%S %p")
            self.login_datetime_label.config(text=formatted)
        except (AttributeError, RuntimeError):
            pass  # Widget may not exist during logout
        
        # Schedule next update
        try:
            self.root.after(1000, self._update_login_datetime)
        except tk.TclError:
            pass  # Window closed

    def _hide_main_window_for_student(self) -> None:
        """Hide SOC/main window while student-only windows are active."""
        try:
            self.root.withdraw()
        except tk.TclError:
            pass

    def _restore_main_window_from_student(self) -> None:
        """Restore SOC/main window when all student windows are closed."""
        windows = [
            self.student_portal_window,
            self.student_login_window,
            self.student_signup_window,
            self.student_dashboard_window,
        ]
        any_open = False
        for w in windows:
            if w and w.winfo_exists():
                any_open = True
                break

        if any_open:
            return

        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        except tk.TclError:
            pass

    def _open_student_portal_landing(self) -> None:
        """Open the university portal landing page for the student flow."""
        self._hide_main_window_for_student()

        if self.student_portal_window and self.student_portal_window.winfo_exists():
            self.student_portal_window.lift()
            self.student_portal_window.focus_force()
            return

        window = tk.Toplevel(self.root)
        window.title("Air University Online Web Portals")
        window.geometry("980x620")
        window.configure(bg="#ffffff")
        window.resizable(False, False)
        self.student_portal_window = window

        top_bar = tk.Frame(window, bg="#32363c", height=52)
        top_bar.pack(fill=tk.X)
        top_bar.pack_propagate(False)

        brand = tk.Frame(top_bar, bg="#32363c")
        brand.pack(side=tk.LEFT, padx=18)
        tk.Label(brand, text="AIR UNIVERSITY", bg="#32363c", fg="#ffffff", font=("Arial", 15, "bold")).pack(anchor="w")
        tk.Label(
            brand,
            text="Federal Chartered Public Sector University",
            bg="#32363c",
            fg="#e5e7eb",
            font=("Arial", 8),
        ).pack(anchor="w")

        links = tk.Frame(top_bar, bg="#32363c")
        links.pack(side=tk.RIGHT, padx=18)
        tk.Label(links, text="AU Portals", bg="#32363c", fg="#ffffff", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=8)
        tk.Label(links, text="AU Website", bg="#32363c", fg="#9ca3af", font=("Arial", 10)).pack(side=tk.LEFT, padx=8)

        body = tk.Frame(window, bg="#ffffff")
        body.pack(fill=tk.BOTH, expand=True, padx=24, pady=18)

        tk.Label(body, text="Online Web Portals", bg="#ffffff", fg="#111827", font=("Arial", 22)).pack(pady=(0, 10))

        hero = tk.Canvas(body, width=760, height=150, bg="#dbeafe", highlightthickness=0)
        hero.pack()
        hero.create_rectangle(0, 0, 760, 150, fill="#c7d2fe", outline="")
        hero.create_text(380, 58, text="AIR UNIVERSITY", fill="#1f2937", font=("Arial", 20, "bold"))
        hero.create_text(380, 92, text="Student Portal Preview", fill="#1f2937", font=("Arial", 11))
        hero.create_rectangle(18, 18, 128, 132, fill="#1e3a8a", outline="")
        hero.create_text(73, 52, text="AU", fill="#ffffff", font=("Arial", 28, "bold"))
        hero.create_text(73, 87, text="PORTAL", fill="#ffffff", font=("Arial", 11, "bold"))

        action_row = tk.Frame(body, bg="#ffffff")
        action_row.pack(anchor="w", pady=16)

        def portal_button(parent, text, command):
            return tk.Button(
                parent,
                text=text,
                command=command,
                bg="#1d4ed8",
                fg="#ffffff",
                font=("Arial", 10, "bold"),
                relief="flat",
                padx=16,
                pady=8,
                cursor="hand2",
                activebackground="#1e40af",
            )

        card = tk.Frame(body, bg="#f8fafc", relief="solid", bd=1)
        card.pack(fill=tk.X, pady=(8, 0))
        tk.Label(card, text="AIR UNIVERSITY ISLAMABAD CAMPUS", bg="#111111", fg="#ffffff", font=("Arial", 14, "bold")).pack(fill=tk.X)
        tk.Label(card, text="Online Admission System", bg="#f8fafc", fg="#111827", font=("Arial", 14, "bold")).pack(pady=(20, 4))
        tk.Label(card, text="Air University Online Admission System", bg="#f8fafc", fg="#1d4ed8", font=("Arial", 10)).pack()

        portal_login_button = tk.Button(
            card,
            text="Student Portal Login",
            command=self._open_student_login_window,
            bg="#1d4ed8",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=18,
            pady=8,
            cursor="hand2",
        )
        portal_login_button.pack(pady=18)

        def on_close() -> None:
            try:
                window.destroy()
            except tk.TclError:
                pass
            self.student_portal_window = None
            self._restore_main_window_from_student()

        window.protocol("WM_DELETE_WINDOW", on_close)

        window.focus_force()

    def _open_student_login_window(self) -> None:
        """Open the student login dialog with username, password, and OTP."""
        self._hide_main_window_for_student()

        if self.student_login_window and self.student_login_window.winfo_exists():
            self.student_login_window.lift()
            self.student_login_window.focus_force()
            return

        window = tk.Toplevel(self.root)
        window.title("Student Portal Login")
        window.geometry("520x360")
        window.configure(bg="#ffffff")
        window.resizable(False, False)
        self.student_login_window = window

        outer = tk.Frame(window, bg="#ffffff", padx=20, pady=20)
        outer.pack(fill=tk.BOTH, expand=True)

        tk.Label(outer, text="Student Portal Login", bg="#ffffff", fg="#111827", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(outer, text="Use the credentials you created in Sign Up. OTP is sent to your registered email.", bg="#ffffff", fg="#4b5563", font=("Arial", 9)).pack(anchor="w", pady=(0, 12))

        form = tk.Frame(outer, bg="#ffffff")
        form.pack(fill=tk.X)

        tk.Label(form, text="Username", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=0, column=0, sticky="w", pady=6)
        self.student_username_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.student_username_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=6)

        tk.Label(form, text="Password", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=6)
        self.student_password_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1, show="*")
        self.student_password_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=6)

        tk.Label(form, text="OTP", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=2, column=0, sticky="w", pady=6)
        self.student_otp_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.student_otp_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=6)

        self.student_otp_label = tk.Label(form, text="OTP not generated yet.", bg="#ffffff", fg="#1d4ed8", font=("Arial", 9, "italic"))
        self.student_otp_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 4))

        form.columnconfigure(1, weight=1)

        btn_row = tk.Frame(outer, bg="#ffffff")
        btn_row.pack(fill=tk.X, pady=(10, 0))

        tk.Button(
            btn_row,
            text="Send OTP",
            command=self._generate_student_otp,
            bg="#2563eb",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_row,
            text="Verify & Login",
            command=self._verify_student_login,
            bg="#2f855a",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_row,
            text="Sign Up",
            command=self._open_student_signup_window,
            bg="#d97706",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_row,
            text="Close",
            command=lambda: (window.destroy(), setattr(self, "student_login_window", None), self._restore_main_window_from_student()),
            bg="#9ca3af",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

        def on_close() -> None:
            try:
                window.destroy()
            except tk.TclError:
                pass
            self.student_login_window = None
            self._restore_main_window_from_student()

        window.protocol("WM_DELETE_WINDOW", on_close)

        window.focus_force()

    def _load_student_accounts(self) -> dict[str, dict[str, Any]]:
        """Load file-backed student credentials."""
        if not self.student_accounts_file.exists():
            return {}

        try:
            data = json.loads(self.student_accounts_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                normalized: dict[str, dict[str, Any]] = {}
                for username, record in data.items():
                    if isinstance(record, dict):
                        normalized[str(username).strip().lower()] = record
                return normalized
        except Exception:
            pass

        return {}

    def _save_student_accounts(self) -> None:
        """Persist student credentials to disk."""
        self._expect_student_accounts_mutation = True
        self.student_accounts_file.write_text(json.dumps(self.student_accounts, indent=2), encoding="utf-8")


    def _student_password_hash(self, username: str, password: str, salt: str) -> str:
        payload = f"{username.strip().lower()}::{salt}::{password}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _student_account_for(self, username: str) -> dict[str, Any] | None:
        return self.student_accounts.get(username.strip().lower())

    def _open_student_signup_window(self) -> None:
        """Open the student sign-up form."""
        self._hide_main_window_for_student()

        if self.student_signup_window and self.student_signup_window.winfo_exists():
            self.student_signup_window.lift()
            self.student_signup_window.focus_force()
            return

        window = tk.Toplevel(self.root)
        window.title("Student Sign Up")
        window.geometry("520x390")
        window.configure(bg="#ffffff")
        window.resizable(False, False)
        self.student_signup_window = window

        outer = tk.Frame(window, bg="#ffffff", padx=20, pady=20)
        outer.pack(fill=tk.BOTH, expand=True)

        tk.Label(outer, text="Student Sign Up", bg="#ffffff", fg="#111827", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(outer, text="Create a dummy student account. The password is stored securely as a hash.", bg="#ffffff", fg="#4b5563", font=("Arial", 9)).pack(anchor="w", pady=(0, 12))

        form = tk.Frame(outer, bg="#ffffff")
        form.pack(fill=tk.X)

        tk.Label(form, text="Username", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=0, column=0, sticky="w", pady=6)
        self.student_signup_username_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.student_signup_username_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=6)

        tk.Label(form, text="Email", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=6)
        self.student_signup_email_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        self.student_signup_email_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=6)

        tk.Label(form, text="Password", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=2, column=0, sticky="w", pady=6)
        self.student_signup_password_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1, show="*")
        self.student_signup_password_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=6)

        tk.Label(form, text="Confirm Password", bg="#ffffff", fg="#111827", font=("Arial", 10)).grid(row=3, column=0, sticky="w", pady=6)
        self.student_signup_confirm_entry = tk.Entry(form, width=34, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1, show="*")
        self.student_signup_confirm_entry.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=6)

        form.columnconfigure(1, weight=1)

        tk.Button(
            outer,
            text="Create Account",
            command=self._register_student_account,
            bg="#1d4ed8",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            padx=14,
            pady=8,
            cursor="hand2",
        ).pack(anchor="w", pady=(12, 0))

        def on_close() -> None:
            try:
                window.destroy()
            except tk.TclError:
                pass
            self.student_signup_window = None
            self._restore_main_window_from_student()

        window.protocol("WM_DELETE_WINDOW", on_close)

        window.focus_force()

    def _register_student_account(self) -> None:
        username = self.student_signup_username_entry.get().strip()
        email = self.student_signup_email_entry.get().strip()
        password = self.student_signup_password_entry.get().strip()
        confirm_password = self.student_signup_confirm_entry.get().strip()

        if not username or not email or not password or not confirm_password:
            messagebox.showerror("Error", "All sign-up fields are required.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        key = username.lower()
        if key in self.student_accounts:
            messagebox.showerror("Error", "That username already exists.")
            return

        geo = self.risk_scorer.get_geo_vpn_risk(ip=self._get_local_ip(), home_country="Pakistan")
        reg_country = str(geo.get("country", "Unknown"))

        salt = secrets.token_hex(16)
        otp_secret = self.mfa_handler.generate_secret_for_user(f"student::{key}")
        self.student_accounts[key] = {
            "username": username,
            "email": email,
            "password_hash": self._student_password_hash(username, password, salt),
            "salt": salt,
            "otp_secret": otp_secret,
            "registered_country": reg_country,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_student_accounts()

        messagebox.showinfo("Success", "Student account created successfully.")
        if self.student_signup_window and self.student_signup_window.winfo_exists():
            self.student_signup_window.destroy()
        self._open_student_login_window()
        self.student_username_entry.delete(0, tk.END)
        self.student_username_entry.insert(0, username)

    def _student_login_record(self, username: str, password: str) -> dict[str, Any] | None:
        record = self._student_account_for(username)
        if not record:
            return None

        expected = self._student_password_hash(username, password, str(record.get("salt", "")))
        if expected != record.get("password_hash"):
            return None

        return record

    def _generate_student_otp(self) -> None:
        """Generate and email an OTP for the signed-up student account."""
        username_entry = getattr(self, "student_username_entry", None)
        password_entry = getattr(self, "student_password_entry", None)
        if username_entry is None or password_entry is None:
            return

        student_name = username_entry.get().strip()
        password = password_entry.get().strip()

        if not student_name or not password:
            messagebox.showerror("Error", "Enter your username and password first.")
            return

        record = self._student_login_record(student_name, password)
        if not record:
            messagebox.showerror("Error", "Invalid student credentials. Sign up first or check your password.")
            return

        student_key = f"student::{student_name.lower()}"
        self.student_otp_secret_key = student_key
        self.mfa_handler.user_secrets[student_key] = str(record.get("otp_secret", ""))
        otp = self.mfa_handler.send_otp(student_key, str(record.get("email", "")))
        self.student_otp_label.config(text=f"OTP sent to {record.get('email', 'registered email')} and valid for 2 minutes.")
        if otp:
            messagebox.showinfo("Student OTP", f"OTP sent to {record.get('email', 'registered email')}.")
        else:
            messagebox.showwarning("Student OTP", f"OTP generation completed for {record.get('email', 'registered email')}, but email delivery may have failed.")

    # ------------------------------------------------------------------
    # Student portal — security, SOC queue, file integrity
    # ------------------------------------------------------------------

    STUDENT_MALICIOUS_EXTENSIONS = {
        ".exe", ".php", ".bat", ".sh", ".js", ".vbs", ".ps1", ".msi",
    }
    STUDENT_SCREEN_CAPTURE_PROCS = {
        "snippingtool.exe", "snip & sketch", "obs64.exe", "obs32.exe", "obs.exe",
        "fraps.exe", "bandicam.exe", "sharex.exe", "xsplit.core.exe", "camtasia.exe",
        "ms-screenclip.exe", "screenrec.exe",
    }

    def _prime_file_integrity_baseline(self) -> None:
        try:
            if self.sessions_log.exists():
                self._last_sessions_log_hash = hashlib.sha256(
                    self.sessions_log.read_bytes()
                ).hexdigest()
            if self.student_accounts_file.exists():
                self._last_student_accounts_hash = hashlib.sha256(
                    self.student_accounts_file.read_bytes()
                ).hexdigest()
        except OSError:
            pass

    def _file_integrity_loop(self) -> None:
        while True:
            time.sleep(4)
            try:
                if self.sessions_log.exists():
                    h = hashlib.sha256(self.sessions_log.read_bytes()).hexdigest()
                    if not self._last_sessions_log_hash or h != self._last_sessions_log_hash:
                        self._last_sessions_log_hash = h
                    self._expect_sessions_log_mutation = False
                if self.student_accounts_file.exists():
                    h2 = hashlib.sha256(self.student_accounts_file.read_bytes()).hexdigest()
                    if not self._last_student_accounts_hash or h2 != self._last_student_accounts_hash:
                        self._last_student_accounts_hash = h2
                    self._expect_student_accounts_mutation = False
            except Exception:
                pass

    def _merge_persisted_alerts_into_memory(self) -> None:
        self.session_manager.reload_from_disk()
        raw = self.session_manager.sessions.get("__persistent_alerts")
        if not isinstance(raw, list):
            return
        known = {str(a.get("id")) for a in ALERTS if isinstance(a, dict) and a.get("id")}
        for p in raw[-300:]:
            if not isinstance(p, dict):
                continue
            pid = str(p.get("id", ""))
            if pid and pid not in known:
                ALERTS.append(dict(p))
                known.add(pid)

    def _poll_soc_alerts_loop(self) -> None:
        try:
            self._merge_persisted_alerts_into_memory()
            for rec in self.session_manager.list_open_soc_pending():
                aid = str(rec.get("id", ""))
                sev = str(rec.get("severity", "")).upper()
                if sev not in {"CRITICAL", "HIGH"} or not aid:
                    continue
                if aid in self._soc_shown_alert_ids:
                    continue
                if self.rbac_manager.is_staff_role(self.current_role) and self.current_session_id:
                    self._soc_shown_alert_ids.add(aid)
                    self.root.after(0, lambda r=dict(rec): self._show_soc_blocking_popup(r))
                t = self._soc_alert_timers.get(aid)
                if t and t.is_alive():
                    continue
                if aid not in self._soc_timers_started:
                    self._soc_timers_started.add(aid)
                    timer = threading.Timer(self.SOC_ALERT_TIMEOUT, lambda rid=aid: self._soc_auto_timeout_worker(rid))
                    timer.daemon = True
                    self._soc_alert_timers[aid] = timer
                    timer.start()
        except Exception:
            pass
        self.root.after(5000, self._poll_soc_alerts_loop)

    def _soc_auto_timeout_worker(self, alert_id: str) -> None:
        res = self.session_manager.try_resolve_soc_pending(
            alert_id, soc_username="SYSTEM", resolution="auto_timeout", detail="SOC response timeout"
        )
        if not res.get("ok"):
            return
        rec = res.get("record") or {}
        sid = str(rec.get("student_session_id", ""))
        self.root.after(0, lambda: self._finalize_soc_decision(alert_id, sid, "auto_timeout", rec))

    def _finalize_soc_decision(self, alert_id: str, student_session_id: str, kind: str, rec: dict[str, Any]) -> None:
        popup = self._soc_popup_windows.pop(alert_id, None)
        if popup and popup.winfo_exists():
            try:
                popup.destroy()
            except tk.TclError:
                pass
        t = self._soc_alert_timers.pop(alert_id, None)
        if t and t.is_alive():
            try:
                t.cancel()
            except Exception:
                pass
        stu = self.student_dashboards.get(student_session_id)
        if kind in {"auto_timeout", "block_student"}:
            self._expect_sessions_log_mutation = True
            if student_session_id:
                self.session_manager.invalidate_session(student_session_id, f"SOC action: {kind}")
            if stu and stu.get("window") and stu["window"].winfo_exists():
                try:
                    messagebox.showerror(
                        "Session ended",
                        "Your session has been terminated by security policy."
                        if kind == "auto_timeout"
                        else "Your session has been terminated by the security team.",
                        parent=stu["window"],
                    )
                    stu["window"].destroy()
                except tk.TclError:
                    pass
            self.student_dashboards.pop(student_session_id, None)
            msg = (
                f"AUTO-TERMINATED: SOC team failed to respond within 5 seconds for {rec.get('threat_type', 'threat')}"
                if kind == "auto_timeout"
                else f"Session terminated by SOC for {rec.get('threat_type', 'threat')}"
            )
            self.threat_handler.send_alert_to_dashboard(msg, severity="CRITICAL", extra={"source": "soc_timer", "alert_id": alert_id})
        elif kind == "dismiss":
            self.threat_handler.send_alert_to_dashboard(
                f"Alert dismissed as false positive for {rec.get('student_username', 'student')}",
                severity="INFO",
                extra={"source": "soc_dismiss", "alert_id": alert_id},
            )
        self._soc_timers_started.discard(alert_id)
        self._refresh_alerts()
        self._refresh_sessions()

    def _show_soc_blocking_popup(self, rec: dict[str, Any]) -> None:
        alert_id = str(rec.get("id", ""))
        if not alert_id:
            return
        popup = tk.Toplevel(self.root)
        popup.title("SOC — IMMEDIATE RESPONSE REQUIRED")
        popup.configure(bg="#7f1d1d")
        popup.geometry("520x320")
        popup.attributes("-topmost", True)
        popup.resizable(False, False)
        popup.transient(self.root)
        try:
            popup.attributes("-toolwindow", False)
        except tk.TclError:
            pass
        self._soc_popup_windows[alert_id] = popup

        tk.Label(
            popup,
            text="CRITICAL / HIGH SECURITY ALERT",
            bg="#7f1d1d",
            fg="#ffffff",
            font=("Arial", 16, "bold"),
        ).pack(pady=(16, 8))

        body = (
            f"Student: {rec.get('student_username', '')}\n"
            f"Threat: {rec.get('threat_type', '')}\n"
            f"Severity: {rec.get('severity', '')}\n"
            f"Detail: {rec.get('message', '')}"
        )
        tk.Label(popup, text=body, bg="#7f1d1d", fg="#fef2f2", font=("Arial", 11), justify=tk.LEFT).pack(padx=16, pady=8)

        countdown = tk.Label(popup, text=str(int(self.SOC_ALERT_TIMEOUT)), bg="#7f1d1d", fg="#fde047", font=("Arial", 36, "bold"))
        countdown.pack(pady=8)

        btn_row = tk.Frame(popup, bg="#7f1d1d")
        btn_row.pack(pady=12)

        def block_click() -> None:
            soc_name = self.current_username or "soc_operator"
            r = self.session_manager.try_resolve_soc_pending(alert_id, soc_name, "block_student", "manual_block")
            if not r.get("ok"):
                messagebox.showinfo(
                    "SOC",
                    "This alert was already closed by another operator or the automated timeout.",
                    parent=self.root,
                )
                lost = self._soc_popup_windows.pop(alert_id, None)
                if lost and lost.winfo_exists():
                    try:
                        lost.destroy()
                    except tk.TclError:
                        pass
                t2 = self._soc_alert_timers.pop(alert_id, None)
                if t2 and t2.is_alive():
                    try:
                        t2.cancel()
                    except Exception:
                        pass
                self._soc_timers_started.discard(alert_id)
                return
            self._expect_sessions_log_mutation = True
            ssid = str(rec.get("student_session_id", "") or "")
            if ssid:
                self.session_manager.append_session_event(
                    ssid,
                    "soc_manual_block",
                    {"soc_operator": soc_name, "alert_id": alert_id, "summary": f"Session terminated by SOC operator {soc_name}"},
                )
            self.root.after(0, lambda: self._finalize_soc_decision(alert_id, ssid, "block_student", rec))

        def dismiss_click() -> None:
            soc_name = self.current_username or "soc_operator"
            r = self.session_manager.try_resolve_soc_pending(alert_id, soc_name, "dismiss", "false_positive")
            if not r.get("ok"):
                messagebox.showinfo(
                    "SOC",
                    "This alert was already closed by another operator or the automated timeout.",
                    parent=self.root,
                )
                lost = self._soc_popup_windows.pop(alert_id, None)
                if lost and lost.winfo_exists():
                    try:
                        lost.destroy()
                    except tk.TclError:
                        pass
                t2 = self._soc_alert_timers.pop(alert_id, None)
                if t2 and t2.is_alive():
                    try:
                        t2.cancel()
                    except Exception:
                        pass
                self._soc_timers_started.discard(alert_id)
                return
            self._expect_sessions_log_mutation = True
            ssid = str(rec.get("student_session_id", "") or "")
            if ssid:
                self.session_manager.append_session_event(
                    ssid,
                    "soc_false_positive",
                    {"soc_operator": soc_name, "alert_id": alert_id, "summary": f"Alert dismissed by {soc_name}"},
                )
            self._finalize_soc_decision(alert_id, ssid, "dismiss", rec)

        tk.Button(btn_row, text="Block Student Session", command=block_click, bg="#450a0a", fg="#fff", font=("Arial", 11, "bold"), padx=10, pady=8).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_row, text="Dismiss as False Positive", command=dismiss_click, bg="#14532d", fg="#fff", font=("Arial", 11, "bold"), padx=10, pady=8).pack(side=tk.LEFT, padx=8)

        remaining = {"n": int(self.SOC_ALERT_TIMEOUT)}

        def tick() -> None:
            if not popup.winfo_exists():
                return
            remaining["n"] -= 1
            countdown.config(text=str(max(0, remaining["n"])))
            if remaining["n"] <= 0:
                return
            popup.after(1000, tick)

        popup.after(1000, tick)

    def _student_contains_sqli(self, text: str) -> bool:
        t = (text or "").upper()
        patterns = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "--", "/*",
            "XP_", "OR 1=1", "AND 1=1",
        ]
        for p in patterns:
            if p in t:
                return True
        if "'" in text and any(k in t for k in ("SELECT", "OR ", "AND ", "WHERE", "1=1")):
            return True
        if ";" in text and any(k in t for k in ("DROP", "DELETE", "INSERT", "UPDATE")):
            return True
        if any(k in t for k in ("EXEC(", "EXECUTE(", "TRUNCATE", "ALTER TABLE", "INFORMATION_SCHEMA", "PG_SLEEP", "WAITFOR DELAY", "BENCHMARK(")):
            return True
        return False

    def _student_upload_path_suspicious(self, path: str) -> tuple[bool, str]:
        """Detect query-string style paths or SQL fragments in filenames (upload channel)."""
        p = path or ""
        if "?" in p or ("&" in p and "=" in p):
            return True, "query_string_in_path"
        name = Path(p).name.lower()
        for needle in ("select", "union", "drop", "insert", "delete", "update", "cast(", "char(", "0x", "../"):
            if needle in name:
                return True, "suspicious_filename_token"
        return False, ""

    def _student_malicious_filename(self, path: str) -> bool:
        low = (path or "").lower()
        for ext in self.STUDENT_MALICIOUS_EXTENSIONS:
            if low.endswith(ext):
                return True
        return False

    def _student_screen_capture_running(self) -> bool:
        try:
            import psutil as _ps
            for p in _ps.process_iter(attrs=["name"]):
                name = (p.info.get("name") or "").lower()
                if name in self.STUDENT_SCREEN_CAPTURE_PROCS:
                    return True
        except Exception:
            pass
        return False

    def _student_emit_threat(
        self,
        session_id: str,
        username: str,
        severity: str,
        message: str,
        threat_type: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        payload = {
            "source": "student_portal",
            "student_session_id": session_id,
            "student_username": username,
            "threat_type": threat_type,
        }
        if extra:
            payload.update(extra)
        alert = self.threat_handler.send_alert_to_dashboard(message, severity=severity, extra=payload)
        aid = str(alert.get("id", ""))
        self.session_manager.log_alert(session_id, message, severity=severity.lower())
        if severity.upper() in {"CRITICAL", "HIGH"}:
            self.session_manager.append_soc_pending({
                "id": aid,
                "state": "open",
                "severity": severity.upper(),
                "message": message,
                "threat_type": threat_type,
                "student_session_id": session_id,
                "student_username": username,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

    def _notify_portal_database_change(self, audit: dict[str, Any]) -> None:
        """Every simulated DB write generates a dashboard alert + optional student session event."""
        actor_role = str(audit.get("actor_role", "")).strip().lower()
        actor = str(audit.get("actor_username", "")).strip()
        entity = str(audit.get("entity", "")).strip()
        tgt = str(audit.get("target_username", "")).strip().lower()
        op = str(audit.get("operation", "")).strip()
        summary = (
            f"[Portal DB] {entity} {op} by {actor} ({actor_role or 'unknown'})"
            + (f" → target `{tgt}`" if tgt else "")
        )
        staff = self.rbac_manager.is_staff_role(actor_role)
        severity = "INFO"
        if entity == "registrar_override":
            severity = "HIGH"
        elif staff and entity == "portal_profile" and tgt and tgt != actor.lower():
            severity = "HIGH"
        elif entity in {"fee_payment", "portal_message", "library_hold"}:
            severity = "MEDIUM"
        elif entity == "portal_profile":
            severity = "INFO"

        alert = self.threat_handler.send_alert_to_dashboard(
            summary,
            severity=severity,
            extra={
                "source": "portal_db_audit",
                "audit_id": audit.get("id"),
                "entity": entity,
                "actor_session_id": audit.get("actor_session_id"),
                "target_username": tgt,
            },
        )
        st_sid = self.session_manager.find_active_session_id_for_user(tgt, "student") if tgt else None
        if st_sid:
            self.session_manager.append_session_event(
                st_sid,
                "portal_db_change",
                {
                    "audit_id": audit.get("id"),
                    "entity": entity,
                    "operation": op,
                    "actor": actor,
                    "summary": summary,
                },
            )
        if severity.upper() in {"HIGH", "CRITICAL"}:
            pend_sid = st_sid or ""
            self.session_manager.append_soc_pending(
                {
                    "id": str(alert.get("id", "")),
                    "state": "open",
                    "severity": severity.upper(),
                    "message": summary,
                    "threat_type": "portal_db_change",
                    "student_session_id": pend_sid,
                    "student_username": tgt or actor,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )

    def _student_risk_level(self, risk_score: float) -> str:
        if risk_score < 35:
            return "LOW"
        if risk_score < 75:
            return "MEDIUM"
        return "HIGH"

    def _verify_student_login(self) -> None:
        """Verify student credentials, evaluate posture, security checks, and open dashboard."""
        username = getattr(self, "student_username_entry", None)
        password = getattr(self, "student_password_entry", None)
        otp_entry = getattr(self, "student_otp_entry", None)

        if username is None or password is None or otp_entry is None:
            return

        student_username = username.get().strip()
        student_password = password.get().strip()
        entered_otp = otp_entry.get().strip()

        if not student_username or not student_password:
            messagebox.showerror("Error", "Username and password are required.")
            return

        record = self._student_login_record(student_username, student_password)
        if not record:
            messagebox.showerror("Error", "Invalid student username or password.")
            return

        student_key = f"student::{student_username.lower()}"
        self.student_otp_secret_key = student_key
        self.mfa_handler.user_secrets[student_key] = str(record.get("otp_secret", ""))

        if not self.mfa_handler.verify_otp(self.student_otp_secret_key, entered_otp):
            messagebox.showerror("OTP Failed", "Invalid OTP. Please try again.")
            return

        if not biometric_auth.verify_fingerprint(student_username, "ZTNA Sentinel — Verify your identity to continue"):
            messagebox.showerror("Error", "Fingerprint verification failed. Access denied.")
            return

        if biometric_auth.LAST_BIOMETRIC_STATUS == "verified":
            messagebox.showinfo("Success", "Fingerprint verified successfully")

        self._expect_sessions_log_mutation = True
        dup_sid = self.session_manager.has_active_student_username(student_username)
        if dup_sid:
            # Load session record and check whether the previous session is still backed by a live window.
            try:
                self.session_manager.reload_from_disk()
                prev = self.session_manager.sessions.get(dup_sid, {}) or {}
            except Exception:
                prev = {}

            prev_window_info = self.student_dashboards.get(dup_sid)
            prev_window_alive = False
            try:
                if prev_window_info and isinstance(prev_window_info, dict):
                    w = prev_window_info.get("window")
                    if w and w.winfo_exists():
                        prev_window_alive = True
            except Exception:
                prev_window_alive = False

            # Determine last activity time (events[-1] or login_time)
            stale = False
            try:
                last_ts = None
                evs = prev.get("events") or []
                if evs:
                    last_ts = evs[-1].get("timestamp")
                else:
                    last_ts = prev.get("login_time")
                if last_ts:
                    try:
                        last_dt = datetime.fromisoformat(str(last_ts))
                        if (datetime.now(timezone.utc) - last_dt).total_seconds() > 600:
                            stale = True
                    except Exception:
                        stale = False
            except Exception:
                stale = False

            # If the previous session has no live window or is stale, end it automatically and allow login.
            if (not prev_window_alive) or stale:
                try:
                    self.session_manager.end_session(dup_sid, status="ended")
                except Exception:
                    pass
                # Continue with login (previous session cleaned up)
            else:
                # Live session exists; offer takeover option to allow immediate login and terminate previous session.
                take_over = messagebox.askyesno(
                    "Concurrent session",
                    "An active session for this account exists. Do you want to take over (end the previous session)?",
                )
                if take_over:
                    try:
                        self.session_manager.end_session(dup_sid, status="ended")
                    except Exception:
                        pass
                else:
                    # Log alert for SOC and deny login
                    dup_alert = self.threat_handler.send_alert_to_dashboard(
                        f"Concurrent session attempt — possible account sharing for {student_username}",
                        severity="CRITICAL",
                        extra={"source": "student_concurrent", "existing_session_id": dup_sid},
                    )
                    self.session_manager.append_soc_pending({
                        "id": str(dup_alert.get("id", "")),
                        "state": "open",
                        "severity": "CRITICAL",
                        "message": f"Concurrent session attempt for {student_username}",
                        "threat_type": "concurrent_session",
                        "student_session_id": dup_sid,
                        "student_username": student_username,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
                    messagebox.showerror("Login denied", "This student account already has an active session.")
                    self._expect_sessions_log_mutation = False
                    return

        current_ip = self._get_local_ip()
        geo = self.risk_scorer.get_geo_vpn_risk(ip=current_ip, home_country="Pakistan")
        login_country = str(geo.get("country", "Unknown"))
        reg_country = str(record.get("registered_country") or "").strip()
        if reg_country and login_country and reg_country.lower() != "unknown" and login_country.lower() != reg_country.lower():
            self.threat_handler.send_alert_to_dashboard(
                f"Geo-location mismatch for student {student_username}: registered {reg_country}, login from {login_country}",
                severity="HIGH",
                extra={"source": "student_geo", "session_hint": "pending"},
            )

        lh = datetime.now().hour
        if lh >= 23 or lh < 5:
            self.threat_handler.send_alert_to_dashboard(
                f"After hours access detected for student {student_username}",
                severity="MEDIUM",
                extra={"source": "student_after_hours"},
            )

        posture_result = self.posture_checker.run_checks()
        posture_score = float(posture_result.get("posture_score", 0.0))
        # Use central risk scorer to compute a meaningful risk score (avoids zero baseline)
        try:
            res = self.risk_scorer.calculate_risk(
                posture_score=posture_score,
                login_location="known",
                login_time=datetime.now().strftime("%H:%M:%S"),
                ip_reputation=20.0,
                traffic_behavior_score=0.0,
            )
            risk_score = float(res.get("risk_score", 1.0))
        except Exception:
            risk_score = max(1.0, round(max(0.0, min(100.0, 100.0 - posture_score)), 2))
        risk_score = max(1.0, float(risk_score))
        risk_level = self._student_risk_level(risk_score)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if risk_score >= 75.0:
            self._expect_sessions_log_mutation = True
            blocked_session = self.session_manager.create_session(
                username=student_username,
                role="student",
                ip=current_ip,
                risk_score=risk_score,
                accessed_apps=["student_portal"],
                status="blocked",
                extra_fields={
                    "device_posture_score": posture_score,
                    "portal": "student",
                    "auth_factors": ["password", "otp", "posture"],
                },
            )
            self.session_manager.append_session_event(
                blocked_session["session_id"],
                "student_login_blocked",
                {
                    "username": student_username,
                    "ip": blocked_session["ip"],
                    "device_posture_score": posture_score,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "reason": "Risk threshold 75+",
                    "summary": "Student login blocked (high risk)",
                },
            )
            messagebox.showerror(
                "Access Denied",
                f"Student access blocked due to high risk.\n\nRisk Score: {risk_score:.1f}\nPosture Score: {posture_score:.1f}",
            )
            self._close_student_portal_windows()
            self._expect_sessions_log_mutation = False
            return

        session_token = str(uuid.uuid4())
        self._expect_sessions_log_mutation = True
        session = self.session_manager.create_session(
            username=student_username,
            role="student",
            ip=current_ip,
            risk_score=risk_score,
            accessed_apps=["student_portal"],
            status="active",
            session_id=str(uuid.uuid4()),
            extra_fields={
                "device_posture_score": posture_score,
                "portal": "student",
                "auth_factors": ["password", "otp", "posture"],
            },
        )
        # Removed debug print that exposed session keys during login
        self.session_manager.register_student_security_fields(
            session["session_id"],
            session_token,
            reg_country or login_country,
            current_ip,
        )
        self.session_manager.append_session_event(
            session["session_id"],
            "student_login",
            {
                "username": student_username,
                "ip": session["ip"],
                "device_posture_score": posture_score,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "login_time": current_time,
                "session_token": session_token,
                "summary": f"Student login at {current_time}",
            },
        )

        alert = self.threat_handler.send_alert_to_dashboard(
            message=f"New Student Login: {student_username} at {current_time}",
            severity="INFO",
            extra={
                "source": "student_login",
                "session_id": session["session_id"],
                "username": student_username,
                "ip": session["ip"],
                "device_posture_score": posture_score,
                "risk_score": risk_score,
            },
        )

        # Ensure SOC/dashboard views refresh immediately after new student session
        try:
            self._refresh_sessions()
            self._refresh_history()
            self._refresh_alerts()
        except Exception:
            pass

        # Screen capture threat detection disabled - too many false positives
        # if self._student_screen_capture_running():
        #     self._student_emit_threat(
        #         session["session_id"],
        #         student_username,
        #         "HIGH",
        #         "Possible screen capture software detected during student session",
        #         "screen_capture",
        #     )

        self._close_student_portal_windows(hide_only=True)
        self._expect_sessions_log_mutation = False
        self._open_student_dashboard(session, posture_result, risk_score, risk_level, session_token, str(alert.get("id", "")))

    def _close_student_portal_windows(self, hide_only: bool = False) -> None:
        """Close landing/login portal windows. Student dashboards stay open unless hide_only is False."""
        for attr in ("student_login_window", "student_portal_window"):
            window = getattr(self, attr, None)
            if window and window.winfo_exists():
                if hide_only:
                    window.withdraw()
                else:
                    window.destroy()
            setattr(self, attr, None)
        if not hide_only:
            for sid, st in list(self.student_dashboards.items()):
                w = st.get("window")
                if w and w.winfo_exists():
                    try:
                        w.destroy()
                    except tk.TclError:
                        pass
                self.student_dashboards.pop(sid, None)
            self.student_dashboard_window = None
            self._restore_main_window_from_student()

    def _student_guarded_portal_action(
        self,
        window: tk.Toplevel,
        session_id: str,
        session_token: str,
        username: str,
        action_type: str,
        capability: str,
        details: dict[str, Any],
        text_fields: list[str] | None = None,
        file_path: str | None = None,
    ) -> bool:
        """Validate session, threats, RBAC capability; log action. Returns False if blocked."""
        if not self.rbac_manager.student_may_use_capability(capability):
            self.threat_handler.send_alert_to_dashboard(
                f"Privilege escalation attempt by {username} ({capability})",
                severity="HIGH",
                extra={"source": "student_priv_esc", "student_session_id": session_id},
            )
            self.session_manager.log_student_portal_action(
                session_id,
                "privilege_escalation_blocked",
                {"capability": capability, "summary": f"Blocked capability {capability}"},
            )
            messagebox.showerror("Access denied", "This action is not permitted for your role.", parent=window)
            return False

        if text_fields:
            for tf in text_fields:
                if self._student_contains_sqli(tf or ""):
                    self._student_emit_threat(
                        session_id,
                        username,
                        "CRITICAL",
                        f"SQL Injection attempt detected from student {username}",
                        "sql_injection",
                    )
                    messagebox.showerror("Invalid characters detected", "Invalid characters detected", parent=window)
                    return False

        if file_path:
            bad_path, path_reason = self._student_upload_path_suspicious(file_path)
            if bad_path:
                self._student_emit_threat(
                    session_id,
                    username,
                    "HIGH",
                    f"Suspicious upload path from {username} ({path_reason}) — {Path(file_path).name}",
                    "upload_path_injection",
                    extra={"path_sample": Path(file_path).name[:120]},
                )
                messagebox.showerror("Blocked", "Upload path looks like an injection or contains URL query parameters.", parent=window)
                return False

        if file_path and self._student_malicious_filename(file_path):
            fn = Path(file_path).name
            self._student_emit_threat(
                session_id,
                username,
                "CRITICAL",
                f"Malicious file upload attempt detected — {fn}",
                "malicious_upload",
            )
            messagebox.showerror("Blocked", "This file type is not allowed.", parent=window)
            return False

        ip_now = self._get_local_ip()
        chk = self.session_manager.verify_student_session_context(session_id, session_token, ip_now)
        if chk.get("hijack"):
            self._student_emit_threat(
                session_id,
                username,
                "CRITICAL",
                f"Session hijacking attempt detected — Session {session_id} accessed from unauthorized IP {ip_now}",
                "session_hijack",
            )
            self.session_manager.invalidate_session(session_id, "Session hijack")
            messagebox.showerror("Security", "Session invalidated.", parent=window)
            window.destroy()
            self.student_dashboards.pop(session_id, None)
            return False
        if not chk.get("ok") and str(chk.get("reason", "")) == "bad_token":
            self._student_emit_threat(
                session_id,
                username,
                "CRITICAL",
                f"Invalid session cookie for {username} — possible stolen session ID or token reuse on session {session_id}",
                "session_cookie_mismatch",
            )
            messagebox.showerror("Security", "Session cookie does not match this session.", parent=window)
            return False
        if not chk.get("ok"):
            messagebox.showerror("Session", "Session is no longer valid.", parent=window)
            return False

        # Screen capture threat detection disabled - too many false positives
        # if self._student_screen_capture_running():
        #     self._student_emit_threat(
        #         session_id,
        #         username,
        #         "HIGH",
        #         "Possible screen capture software detected during student session",
        #         "screen_capture",
        #     )

        self.session_manager.log_student_portal_action(
            session_id,
            action_type,
            {"summary": details.get("summary", action_type), **{k: v for k, v in details.items() if k != "summary"}},
        )

        cnt = self.session_manager.student_action_rate_count(session_id)
        if cnt > 10:
            self.threat_handler.send_alert_to_dashboard(
                f"Suspicious rapid activity detected from {username} — possible automated attack",
                severity="HIGH",
                extra={"source": "student_rapid", "student_session_id": session_id},
            )

        self._refresh_sessions()
        self._refresh_alerts()
        return True

    def _open_student_dashboard(
        self,
        session: dict[str, Any],
        posture_result: dict[str, Any],
        risk_score: float,
        risk_level: str,
        session_token: str,
        login_alert_id: str = "",
    ) -> None:
        """Functional student portal with logging, monitoring hooks, and multi-session support."""
        self._hide_main_window_for_student()

        sid = str(session.get("session_id", ""))
        username = str(session.get("username", "student"))

        window = tk.Toplevel(self.root)
        window.title(f"Student Dashboard — {username}")
        window.geometry("1380x800")
        window.configure(bg="#edf4fb")
        self.student_dashboard_window = window
        self.student_dashboards[sid] = {
            "window": window,
            "session_token": session_token,
            "username": username,
            "session_id": sid,
        }

        def on_close() -> None:
            self._expect_sessions_log_mutation = True
            try:
                self.session_manager.end_session(sid, status="ended")
            except Exception:
                pass
            self.student_dashboards.pop(sid, None)
            if self.student_dashboard_window == window:
                self.student_dashboard_window = None
            window.destroy()
            self._restore_main_window_from_student()

        window.protocol("WM_DELETE_WINDOW", on_close)

        header = tk.Frame(window, bg="#1d5a92", height=42)
        header.pack(fill=tk.X)
        tk.Label(header, text="Student Portal", bg="#1d5a92", fg="#fff", font=("Arial", 14, "bold")).pack(side=tk.LEFT, padx=12)
        tk.Label(header, text=f"Logged in: {username}", bg="#1d5a92", fg="#fff", font=("Arial", 10)).pack(side=tk.RIGHT, padx=12)

        nb = ttk.Notebook(window)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        dash = tk.Frame(nb, bg="#ffffff")
        courses_f = tk.Frame(nb, bg="#ffffff")
        grades_f = tk.Frame(nb, bg="#ffffff")
        time_f = tk.Frame(nb, bg="#ffffff")
        att_f = tk.Frame(nb, bg="#ffffff")
        nb.add(dash, text="Dashboard")
        nb.add(courses_f, text="Courses")
        nb.add(grades_f, text="Grades")
        nb.add(time_f, text="Timetable")
        nb.add(att_f, text="Attendance")
        campus_f = tk.Frame(nb, bg="#ffffff")
        nb.add(campus_f, text="Campus & Services")

        # --- Dashboard
        info_fr = tk.LabelFrame(dash, text="Live session information", bg="#ffffff", font=("Arial", 11, "bold"))
        info_fr.pack(fill=tk.X, padx=8, pady=6)
        live_lbl = tk.Label(
            info_fr,
            text="",
            bg="#ffffff",
            fg="#111",
            font=("Courier", 10),
            justify=tk.LEFT,
        )
        live_lbl.pack(anchor="w", padx=8, pady=4)

        sec_fr = tk.LabelFrame(dash, text="Session security status", bg="#ffffff", font=("Arial", 11, "bold"))
        sec_fr.pack(fill=tk.X, padx=8, pady=6)
        sec_txt = tk.Text(sec_fr, height=4, width=140, bg="#f1f5f9", font=("Arial", 10))
        sec_txt.pack(fill=tk.X, padx=6, pady=4)

        probe_fr = tk.Frame(dash, bg="#ffffff")
        probe_fr.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(probe_fr, text="Security lab:", bg="#ffffff").pack(side=tk.LEFT)
        tk.Button(
            probe_fr,
            text="Attempt restricted SOC action (demo)",
            command=lambda: self._student_guarded_portal_action(
                window, sid, session_token, username, "priv_probe", "soc_console_fake",
                {"summary": "User attempted forbidden SOC console"},
            ),
            bg="#fecaca",
        ).pack(side=tk.LEFT, padx=8)
        tk.Button(
            probe_fr,
            text="Simulate wrong session cookie (lab)",
            command=lambda: self._student_guarded_portal_action(
                window, sid, str(uuid.uuid4()), username, "cookie_lab", "student_dashboard_view",
                {"summary": "Lab: wrong token with valid session id"},
            ),
            bg="#fde68a",
        ).pack(side=tk.LEFT, padx=8)

        def refresh_dash() -> None:
            self.session_manager.reload_from_disk()
            sess = self.session_manager.sessions.get(sid, {})
            live_lbl.config(
                text=(
                    f"Session ID: {sid}\n"
                    f"Login time: {str(sess.get('login_time', ''))[:22]}\n"
                    f"IP: {sess.get('ip', '')}\n"
                    f"Risk score: {float(sess.get('risk_score', 0)):.2f}  |  Token: {session_token[:8]}…"
                )
            )
            sec_txt.delete("1.0", tk.END)
            sec_txt.insert(
                tk.END,
                f"Posture score: {float(posture_result.get('posture_score', 0)):.1f}\n"
                f"Risk level at login: {risk_level}\n"
                f"Screen capture scan: periodic on action\n"
                f"Session binding: IP {sess.get('authorized_ip', '')} / Country {sess.get('registered_country', '')}\n"
                f"Session cookie (opaque, do not share): {str(sess.get('session_cookie', session_token))[:14]}…\n",
            )
            # Student dashboard intentionally does not show the activity feed.

        refresh_dash()

        def dash_tick() -> None:
            if not window.winfo_exists():
                return
            refresh_dash()
            window.after(4000, dash_tick)

        window.after(4000, dash_tick)

        inact_state = {"last": time.time(), "warn": None}

        def inact_tick() -> None:
            if not window.winfo_exists():
                return
            if time.time() - inact_state["last"] > 180:
                if inact_state["warn"] is None:
                    self.threat_handler.send_alert_to_dashboard(
                        f"Student session inactive for 3 minutes ({username})",
                        severity="INFO",
                        extra={"source": "student_inactive", "student_session_id": sid},
                    )
                    inact_state["warn"] = time.time()
                    cd = tk.Toplevel(window)
                    cd.title("Inactivity")
                    cd.attributes("-topmost", True)
                    tk.Label(cd, text="No activity for 3 minutes. Auto logout in 2:00 unless you continue.", padx=12, pady=12).pack()
                    rem = {"s": 120}

                    def cdtick() -> None:
                        if not cd.winfo_exists():
                            return
                        rem["s"] -= 1
                        if rem["s"] <= 0:
                            self._expect_sessions_log_mutation = True
                            self.session_manager.end_session(sid, status="ended")
                            cd.destroy()
                            window.destroy()
                            self.student_dashboards.pop(sid, None)
                            return
                        cd.after(1000, cdtick)

                    cd.after(1000, cdtick)
            window.after(15000, inact_tick)

        window.after(15000, inact_tick)

        def touch() -> None:
            inact_state["last"] = time.time()
            inact_state["warn"] = None

        tab_guard_once: set[str] = set()

        def on_notebook_tab(_e=None) -> None:
            touch()
            try:
                idx = nb.index(nb.select())
            except tk.TclError:
                return
            tab_name = str(nb.tab(idx, "text"))
            cap_map = {
                "Courses": ("student_courses_view", "courses_tab_open"),
                "Timetable": ("student_timetable_view", "timetable_tab_open"),
                "Attendance": ("student_attendance_view", "attendance_tab_open"),
                "Campus & Services": ("student_campus_services_view", "campus_tab_open"),
            }
            if tab_name in cap_map and tab_name not in tab_guard_once:
                tab_guard_once.add(tab_name)
                cap, atype = cap_map[tab_name]
                self._student_guarded_portal_action(
                    window, sid, session_token, username, atype, cap,
                    {"summary": f"Opened {tab_name} tab"},
                )

        nb.bind("<<NotebookTabChanged>>", on_notebook_tab)

        # --- Courses (hardcoded)
        courses = [
            {"code": "CY223", "title": "Network Security", "credits": 3, "instructor": "Dr. Khan"},
            {"code": "CS325", "title": "Operating Systems", "credits": 3, "instructor": "Dr. Ali"},
            {"code": "CY256", "title": "Digital Forensics", "credits": 3, "instructor": "Dr. Raza"},
        ]
        tk.Label(courses_f, text="Enrolled courses (demo data)", bg="#ffffff", font=("Arial", 12, "bold")).pack(anchor="w", padx=8)
        lb = tk.Listbox(courses_f, height=8, width=60, font=("Arial", 11))
        lb.pack(side=tk.LEFT, padx=8, pady=8, fill=tk.Y)
        for c in courses:
            lb.insert(tk.END, f"{c['code']} — {c['title']}")
        det = tk.Text(courses_f, height=10, width=80, bg="#f8fafc", font=("Arial", 10))
        det.pack(side=tk.LEFT, padx=8, pady=8, fill=tk.BOTH, expand=True)

        def show_course(_e=None) -> None:
            touch()
            sel = lb.curselection()
            if not sel:
                return
            c = courses[sel[0]]
            det.delete("1.0", tk.END)
            det.insert(tk.END, json.dumps(c, indent=2))
            self._student_guarded_portal_action(
                window, sid, session_token, username, "course_view", "student_course_detail",
                {"summary": f"Viewed course {c['code']}", "course": c["code"]},
            )

        lb.bind("<<ListboxSelect>>", show_course)

        def sim_download() -> None:
            touch()
            path = filedialog.askopenfilename(parent=window, title="Simulate download — pick any file")
            if not path:
                return
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "course_download", "student_course_download",
                {"summary": f"Download simulation path {path}"}, file_path=path,
            ):
                return

        def sim_submit() -> None:
            touch()
            path = filedialog.askopenfilename(parent=window, title="Simulate assignment upload")
            if not path:
                return
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "assignment_submit", "student_assignment_submit",
                {"summary": f"Assignment upload {Path(path).name}"}, file_path=path,
            ):
                return

        bf = tk.Frame(courses_f, bg="#ffffff")
        bf.pack(fill=tk.X, padx=8, pady=4)
        tk.Button(bf, text="Download course material (simulated)", command=sim_download, bg="#2563eb", fg="#fff").pack(side=tk.LEFT, padx=4)
        tk.Button(bf, text="Submit assignment (simulated)", command=sim_submit, bg="#16a34a", fg="#fff").pack(side=tk.LEFT, padx=4)

        # --- Grades
        rows = [
            ("Fall-2024", "3.10", "Good standing"),
            ("Spring-2025", "3.28", "Dean's list eligible"),
            ("Fall-2025", "3.35", "In progress"),
        ]
        tk.Label(grades_f, text="Semester grades", bg="#ffffff", font=("Arial", 12, "bold")).pack(anchor="w", padx=8)
        gt = ttk.Treeview(grades_f, columns=("sem", "gpa", "note"), show="headings", height=6)
        gt.heading("sem", text="Semester")
        gt.heading("gpa", text="GPA")
        gt.heading("note", text="Notes")
        gt.pack(fill=tk.X, padx=8, pady=4)
        for r in rows:
            gt.insert("", tk.END, values=r)
        gdet = tk.Text(grades_f, height=6, width=100, bg="#f8fafc")
        gdet.pack(fill=tk.X, padx=8, pady=4)

        def grade_detail(_e=None) -> None:
            touch()
            sel = gt.selection()
            if not sel:
                return
            vals = gt.item(sel[0], "values")
            gdet.delete("1.0", tk.END)
            gdet.insert(tk.END, f"Breakdown for {vals[0]}: courses averaged with lab components.\nGPA: {vals[1]}\n")
            self._student_guarded_portal_action(
                window, sid, session_token, username, "grade_detail", "student_grades_view",
                {"summary": f"Grade detail {vals[0]}"},
            )

        gt.bind("<<TreeviewSelect>>", grade_detail)
        rev_fr = tk.LabelFrame(grades_f, text="Request grade review", bg="#ffffff")
        rev_fr.pack(fill=tk.X, padx=8, pady=6)
        rev_txt = tk.Text(rev_fr, height=4, width=80)
        rev_txt.pack(side=tk.LEFT, padx=4, pady=4)

        def submit_review() -> None:
            touch()
            body = rev_txt.get("1.0", tk.END).strip()
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "grade_review", "student_grade_review_request",
                {"summary": "Grade review request submitted", "body": body},
                text_fields=[body],
            ):
                return
            rev_txt.delete("1.0", tk.END)
            messagebox.showinfo("Sent", "Review request submitted.", parent=window)

        tk.Button(rev_fr, text="Submit", command=submit_review, bg="#c58a1f", fg="#fff").pack(side=tk.LEFT, padx=4)

        # --- Timetable
        grid_txt = tk.Text(time_f, height=20, width=120, bg="#ffffff", font=("Courier", 10))
        grid_txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        grid_txt.insert(
            tk.END,
            "Weekly Timetable (demo)\n"
            "        Mon        Tue        Wed        Thu        Fri\n"
            "08-10   CY223      CS325      CY256      CY223      Lab\n"
            "10-12   CS325      CY223      CS325      CY256      CY223\n"
            "12-14   Free       CY256      Free       CS325      CY256\n",
        )

        def export_tt() -> None:
            touch()
            path = filedialog.asksaveasfilename(parent=window, defaultextension=".txt", filetypes=[("Text", "*.txt")])
            if not path:
                return
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "timetable_export", "student_timetable_export",
                {"summary": f"Exported timetable to {path}"}, file_path=path,
            ):
                return
            Path(path).write_text(grid_txt.get("1.0", tk.END), encoding="utf-8")
            messagebox.showinfo("Exported", path, parent=window)

        tk.Button(time_f, text="Export timetable as text file", command=export_tt, bg="#1d4ed8", fg="#fff").pack(pady=4)

        # --- Attendance
        at_rows = [("CY223", "92%"), ("CS325", "88%"), ("CY256", "95%")]
        tk.Label(att_f, text="Attendance by course", bg="#ffffff", font=("Arial", 12, "bold")).pack(anchor="w", padx=8)
        at = ttk.Treeview(att_f, columns=("c", "p"), show="headings", height=5)
        at.heading("c", text="Course")
        at.heading("p", text="Attendance %")
        at.pack(fill=tk.X, padx=8, pady=4)
        for r in at_rows:
            at.insert("", tk.END, values=r)
        rel_fr = tk.LabelFrame(att_f, text="Attendance relaxation request", bg="#ffffff")
        rel_fr.pack(fill=tk.X, padx=8, pady=6)
        rel_txt = tk.Text(rel_fr, height=4, width=80)
        rel_txt.pack(side=tk.LEFT, padx=4)

        def submit_rel() -> None:
            touch()
            body = rel_txt.get("1.0", tk.END).strip()
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "attendance_relax", "student_attendance_relaxation_request",
                {"summary": "Attendance relaxation submitted", "body": body},
                text_fields=[body],
            ):
                return
            rel_txt.delete("1.0", tk.END)

        tk.Button(rel_fr, text="Submit", command=submit_rel, bg="#c58a1f", fg="#fff").pack(side=tk.LEFT)

        # --- Campus & Services (interactive + simulated DB for SOC monitoring)
        top_c = tk.Frame(campus_f, bg="#ffffff")
        top_c.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(
            top_c,
            text="Use this area to update your profile, pay fees, message the registrar, and reserve library books. "
            "Each action is written to sessions_log.json and surfaces as alerts/events for the SOC team.",
            bg="#ffffff",
            fg="#334155",
            font=("Arial", 10),
            wraplength=960,
            justify=tk.LEFT,
        ).pack(anchor="w")

        prof_fr = tk.LabelFrame(campus_f, text="Campus profile (simulated DB)", bg="#ffffff")
        prof_fr.pack(fill=tk.X, padx=8, pady=6)
        tk.Label(prof_fr, text="Phone", bg="#ffffff").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        phone_e = tk.Entry(prof_fr, width=44, font=("Arial", 10))
        phone_e.grid(row=0, column=1, sticky="w", padx=4, pady=4)
        tk.Label(prof_fr, text="Bio", bg="#ffffff").grid(row=1, column=0, sticky="nw", padx=4, pady=4)
        bio_t = tk.Text(prof_fr, height=3, width=52, font=("Arial", 10))
        bio_t.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        def refresh_campus() -> None:
            self.session_manager.reload_from_disk()
            pr = self.session_manager.get_portal_profile(username)
            phone_e.delete(0, tk.END)
            phone_e.insert(0, str(pr.get("phone", "")))
            bio_t.delete("1.0", tk.END)
            bio_t.insert("1.0", str(pr.get("bio", "")))
            bal_lbl.config(text=f"Outstanding fee (simulated PKR): {float(pr.get('fee_balance', 0)):.2f}")
            msg_lb.delete(0, tk.END)
            for m in self.session_manager.list_portal_messages_for_student(username):
                ts = str(m.get("timestamp", ""))[:19]
                msg_lb.insert(
                    tk.END,
                    f"{ts} | {m.get('from_user')} → {m.get('to_user')}: {str(m.get('body', ''))[:100]}",
                )

        def save_profile() -> None:
            touch()
            ph = phone_e.get().strip()
            bi = bio_t.get("1.0", tk.END).strip()
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "profile_save", "student_portal_profile_update",
                {"summary": "Updated campus profile", "phone": ph},
                text_fields=[ph, bi],
            ):
                return
            self._expect_sessions_log_mutation = True
            aud = self.session_manager.portal_database_mutation(
                actor_role="student",
                actor_username=username,
                actor_session_id=sid,
                operation="UPSERT",
                entity="portal_profile",
                entity_key=username.lower(),
                payload={"phone": ph, "bio": bi},
                target_username=username,
            )
            self._notify_portal_database_change(aud)
            self._expect_sessions_log_mutation = False
            messagebox.showinfo("Saved", "Profile saved to simulated DB and SOC feed.", parent=window)
            refresh_campus()

        tk.Button(prof_fr, text="Save profile", command=save_profile, bg="#1d4ed8", fg="#fff").grid(row=2, column=1, sticky="w", padx=4, pady=6)

        msg_fr = tk.LabelFrame(campus_f, text="Messages to registrar", bg="#ffffff")
        msg_fr.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        msg_lb = tk.Listbox(msg_fr, height=6, width=110, font=("Courier", 9))
        msg_lb.pack(fill=tk.X, padx=4, pady=4)
        msg_body = tk.Text(msg_fr, height=3, width=80, font=("Arial", 10))
        msg_body.pack(anchor="w", padx=4, pady=4)

        def send_campus_msg() -> None:
            touch()
            body = msg_body.get("1.0", tk.END).strip()
            if not body:
                return
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "campus_message", "student_portal_message_send",
                {"summary": "Campus message to registrar", "body": body},
                text_fields=[body],
            ):
                return
            self._expect_sessions_log_mutation = True
            aud = self.session_manager.portal_database_mutation(
                actor_role="student",
                actor_username=username,
                actor_session_id=sid,
                operation="INSERT",
                entity="portal_message",
                entity_key=username.lower(),
                payload={"body": body, "from_user": username, "to_user": "admin"},
                target_username=username,
            )
            self._notify_portal_database_change(aud)
            self._expect_sessions_log_mutation = False
            msg_body.delete("1.0", tk.END)
            refresh_campus()

        tk.Button(msg_fr, text="Send message", command=send_campus_msg, bg="#0f766e", fg="#fff").pack(anchor="w", padx=4, pady=4)

        fee_fr = tk.LabelFrame(campus_f, text="Tuition (simulated payment)", bg="#ffffff")
        fee_fr.pack(fill=tk.X, padx=8, pady=6)
        bal_lbl = tk.Label(fee_fr, text="", bg="#ffffff", font=("Arial", 11, "bold"))
        bal_lbl.pack(anchor="w", padx=4, pady=4)
        fee_row = tk.Frame(fee_fr, bg="#ffffff")
        fee_row.pack(anchor="w", padx=4, pady=4)
        tk.Label(fee_row, text="Amount PKR", bg="#ffffff").pack(side=tk.LEFT)
        fee_amt = tk.Entry(fee_row, width=12, font=("Arial", 10))
        fee_amt.pack(side=tk.LEFT, padx=8)

        def pay_fee() -> None:
            touch()
            raw = fee_amt.get().strip()
            try:
                amt = float(raw)
            except ValueError:
                messagebox.showerror("Invalid", "Enter a numeric amount.", parent=window)
                return
            if amt <= 0:
                return
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "fee_payment", "student_portal_fee_sim",
                {"summary": f"Simulated fee payment PKR {amt}", "amount": amt},
                text_fields=[raw],
            ):
                return
            self._expect_sessions_log_mutation = True
            aud = self.session_manager.portal_database_mutation(
                actor_role="student",
                actor_username=username,
                actor_session_id=sid,
                operation="INSERT",
                entity="fee_payment",
                entity_key=username.lower(),
                payload={"amount": amt},
                target_username=username,
            )
            self._notify_portal_database_change(aud)
            self._expect_sessions_log_mutation = False
            fee_amt.delete(0, tk.END)
            refresh_campus()

        tk.Button(fee_fr, text="Record payment", command=pay_fee, bg="#15803d", fg="#fff").pack(anchor="w", padx=4, pady=4)

        lib_fr = tk.LabelFrame(campus_f, text="Library reservation", bg="#ffffff")
        lib_fr.pack(fill=tk.X, padx=8, pady=6)
        books = ("INTRO-SEC-101", "OS-Internals", "Forensics-Casebook", "Crypto-Workbook")
        lib_var = tk.StringVar(value=books[0])
        tk.OptionMenu(lib_fr, lib_var, *books).pack(side=tk.LEFT, padx=4)

        def hold_book() -> None:
            touch()
            bk = lib_var.get()
            if not self._student_guarded_portal_action(
                window, sid, session_token, username, "library_hold", "student_portal_library_reserve",
                {"summary": f"Reserved book {bk}", "book": bk},
                text_fields=[bk],
            ):
                return
            self._expect_sessions_log_mutation = True
            aud = self.session_manager.portal_database_mutation(
                actor_role="student",
                actor_username=username,
                actor_session_id=sid,
                operation="INSERT",
                entity="library_hold",
                entity_key=username.lower(),
                payload={"book": bk},
                target_username=username,
            )
            self._notify_portal_database_change(aud)
            self._expect_sessions_log_mutation = False
            messagebox.showinfo("Library", f"Hold recorded for {bk}.", parent=window)

        tk.Button(lib_fr, text="Place hold", command=hold_book, bg="#7c3aed", fg="#fff").pack(side=tk.LEFT, padx=8)

        refresh_campus()

        self._student_guarded_portal_action(
            window, sid, session_token, username, "dashboard_open", "student_dashboard_view",
            {"summary": "Opened functional student dashboard"},
        )

    def _draw_student_cgpa_graph(self, canvas: tk.Canvas, semesters: list[str], cgpas: list[float]) -> None:
        """Draw a small CGPA trend graph for the student dashboard."""
        canvas.delete("all")
        width = int(canvas.winfo_reqwidth())
        height = int(canvas.winfo_reqheight())
        canvas.create_line(50, 210, 510, 210, fill="#cbd5e1", width=2)
        canvas.create_line(50, 30, 50, 210, fill="#cbd5e1", width=2)

        canvas.create_text(35, 35, text="4", fill="#6b7280", font=("Arial", 8))
        canvas.create_text(35, 110, text="3", fill="#6b7280", font=("Arial", 8))
        canvas.create_text(35, 185, text="2", fill="#6b7280", font=("Arial", 8))

        max_value = 4.0
        plot_points = []
        step = 220 if len(cgpas) > 1 else 0
        start_x = 110
        for idx, value in enumerate(cgpas):
            x = start_x + idx * step
            y = 210 - ((value / max_value) * 160)
            plot_points.append((x, y))

        for idx, (x, y) in enumerate(plot_points):
            canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill="#2563eb", outline="#2563eb")
            canvas.create_text(x, y - 12, text=f"CGPA: {cgpas[idx]:.2f}", fill="#0f172a", font=("Arial", 8, "bold"))
            canvas.create_text(x, 230, text=semesters[idx], fill="#374151", font=("Arial", 8))

        if len(plot_points) > 1:
            flat = []
            for x, y in plot_points:
                flat.extend([x, y])
            canvas.create_line(*flat, fill="#2563eb", width=3, smooth=True)

    def _draw_student_credit_graph(self, canvas: tk.Canvas, course_labels: list[str], credit_hours: list[int]) -> None:
        """Draw a dummy bar chart for registered course credit hours."""
        canvas.delete("all")
        canvas.create_line(40, 210, 520, 210, fill="#cbd5e1", width=2)
        canvas.create_line(40, 25, 40, 210, fill="#cbd5e1", width=2)

        if not credit_hours:
            return

        max_hours = max(credit_hours) if max(credit_hours) else 1
        available_width = max(460, int(canvas.winfo_width() or 520) - 90)
        spacing = 16 if len(credit_hours) >= 7 else 28
        bar_width = max(18, int((available_width - (len(credit_hours) - 1) * spacing) / max(1, len(credit_hours))))
        start_x = 54
        for idx, hours in enumerate(credit_hours):
            x1 = start_x + idx * (bar_width + spacing)
            x2 = x1 + bar_width
            bar_height = int((hours / max_hours) * 150)
            y1 = 210 - bar_height
            canvas.create_rectangle(x1, y1, x2, 210, fill="#38bdf8", outline="#38bdf8")
            canvas.create_text((x1 + x2) / 2, y1 - 10, text=str(hours), fill="#0f172a", font=("Arial", 8, "bold"))
            if idx < len(course_labels):
                canvas.create_text((x1 + x2) / 2, 230, text=course_labels[idx], fill="#374151", font=("Arial", 8))

    # ------------------------------------------------------------------
    # Toast Notifications
    # ------------------------------------------------------------------

    def _show_toast_notification(self, message: str, severity: str = "INFO", duration_ms: int = 5000) -> None:
        """Show a bottom-right popup toast notification."""
        # Normalize severity
        severity = severity.upper() if severity else "INFO"
        
        # Play sound for CRITICAL alerts
        if severity == "CRITICAL" and WINSOUND_AVAILABLE:
            try:
                winsound.Beep(1000, 500)  # 1000 Hz for 500 ms
            except Exception:
                pass

        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Create toast window
        toast = tk.Toplevel(self.root)
        toast.attributes('-topmost', True)
        toast.attributes('-alpha', 0.95)
        
        # Determine color based on severity
        from threat_response.response_handler import SEVERITY_COLORS
        bg_color = SEVERITY_COLORS.get(severity, "#2f855a")
        
        # Create label with message
        label = tk.Label(
            toast,
            text=f"[{severity}] {message}",
            bg=bg_color,
            fg="#ffffff",
            font=("Arial", 10),
            padx=20,
            pady=12,
            wraplength=300,
            justify=tk.LEFT,
        )
        label.pack()

        # Position in bottom-right
        toast_width = 350
        toast_height = 80
        x = screen_width - toast_width - 20
        y = screen_height - toast_height - 60
        toast.geometry(f"{toast_width}x{toast_height}+{x}+{y}")
        toast.overrideredirect(True)

        # Auto-destroy after duration
        def destroy_toast():
            try:
                toast.destroy()
            except tk.TclError:
                pass

        self.root.after(duration_ms, destroy_toast)

    def _process_logout(self, is_automatic: bool) -> None:
        """Called by LogoutHandler thread or manual button click."""
        self.root.after(0, self._process_logout_gui, is_automatic)

    def _process_logout_gui(self, is_automatic: bool) -> None:
        """Execute logout actions on the main GUI thread."""
        self._stop_continuous_risk_recalculation()
        self.traffic_monitor.stop()

        if self._personal_status_after_id:
            try:
                self.root.after_cancel(self._personal_status_after_id)
            except tk.TclError:
                pass
            self._personal_status_after_id = None

        if self.current_session_id:
            self.session_manager.end_session(self.current_session_id, status="ended")
            self.current_session_id = None
            
        self.monitoring_active = False
        self.logout_handler.cancel()
        
        # Reset UI
        self._reset_login_form()
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.current_email = ""
        self.risk_label.config(text="")
        self._update_live_risk_badge(None)
        self._set_posture_placeholder()
        self.apply_role_restrictions("guest")
        self.logout_btn.pack_forget()
        
        # Switch to login tab
        self.notebook.select(0)
        
        # Show message
        if is_automatic:
            messagebox.showinfo("Session Timeout", "You have been automatically logged out due to inactivity/timeout (600s).")
        else:
            messagebox.showinfo("Logged Out", "You have been logged out successfully.")

    def _on_app_close(self) -> None:
        """Handle application close (window X / taskbar). Ensure sessions are ended and state persisted."""
        try:
            # Stop background work
            self._stop_continuous_risk_recalculation()
        except Exception:
            pass
        try:
            self.stop_monitoring.set()
        except Exception:
            pass
        try:
            self.traffic_monitor.stop()
        except Exception:
            pass

        # End any active student dashboards
        try:
            self._expect_sessions_log_mutation = True
            for sid in list(self.student_dashboards.keys()):
                try:
                    self.session_manager.end_session(sid, status="ended")
                except Exception:
                    pass
                self.student_dashboards.pop(sid, None)
            # End currently logged-in staff/session if present
            if self.current_session_id:
                try:
                    self.session_manager.end_session(self.current_session_id, status="ended")
                except Exception:
                    pass
                self.current_session_id = None
        finally:
            self._expect_sessions_log_mutation = False

        try:
            self.root.destroy()
        except Exception:
            try:
                self.root.quit()
            except Exception:
                pass
    
    def _handle_login(self) -> None:
        self.current_username = self.username_entry.get().strip()
        user_email = self.email_entry.get().strip()
        self.current_email = user_email
        password = self.password_entry.get().strip()
        self.current_role = self.role_combo.get().strip().lower()
        
        if not self.current_username or not user_email or not password or not self.current_role:
            messagebox.showerror("Error", "All fields are required!")
            self.session_manager.log_login_attempt(
                username=self.current_username or "unknown",
                ip=self._get_local_ip(),
                success=False,
                reason="Missing fields",
            )
            return
        
        # CHECK ACCOUNT LOCKOUT
        lockout_check = self.session_manager.check_account_lockout(self.current_username)
        if lockout_check["is_locked"]:
            remaining_sec = lockout_check["remaining_seconds"]
            minutes = remaining_sec // 60
            seconds = remaining_sec % 60
            messagebox.showerror(
                "Account Locked",
                f"This account is locked due to:\n{lockout_check['reason']}\n\n"
                f"Time remaining: {minutes}m {seconds}s\n\nPlease try again later.",
            )
            self.session_manager.log_login_attempt(
                username=self.current_username,
                ip=self._get_local_ip(),
                success=False,
                reason="Account locked",
            )
            return
        
        self.current_ip = self._get_local_ip()
        
        # Check for suspicious login (different IP than last 3 logins)
        suspicious_check = self.session_manager.is_suspicious_login(self.current_username, self.current_ip)
        if suspicious_check["is_suspicious"]:
            # Log security incident for security engineers
            self._log_security_event(
                "suspicious_login_detected",
                {
                    "username": self.current_username,
                    "current_ip": self.current_ip,
                    "reason": suspicious_check["reason"],
                    "previous_ips": suspicious_check["previous_ips"],
                },
            )
        
        # Before sending OTP: enforce hardcoded Blue Team credentials per selected role
        hardcoded_map = {
            "soc_operator": ("Bhali", "Bhali07"),
            "threat_analyst": ("Ammar", "Ammar16"),
            "security_engineer": ("Hussain", "Hussain18"),
        }
        expected = hardcoded_map.get(self.current_role)
        if expected is not None:
            if not (self.current_username == expected[0] and password == expected[1]):
                messagebox.showerror("Invalid credentials", "Invalid credentials. Access denied.")
                self.session_manager.log_login_attempt(
                    username=self.current_username or "unknown",
                    ip=self._get_local_ip(),
                    success=False,
                    reason="Invalid hardcoded credentials",
                )
                return

        # Generate and send OTP via email (unchanged)
        self.mfa_handler.generate_secret_for_user(self.current_username)
        otp = self.mfa_handler.send_otp(self.current_username, user_email)

        # Show OTP entry frame
        self.otp_frame.grid()
        self.login_btn.config(state="disabled")

        messagebox.showinfo("OTP Sent", f"An OTP code has been sent to:\n{user_email}\n\nCheck your email and enter the code below.")
    
    def _handle_otp_verification(self) -> None:
        entered_otp = self.otp_entry.get().strip()
        
        if self.mfa_handler.verify_otp(self.current_username, entered_otp):
            self.mfa_status_label.config(text="✓ MFA Passed", fg=self.SUCCESS_GREEN)
            self.verify_otp_btn.config(state="disabled")
            
            # Log successful MFA attempt
            self.session_manager.log_login_attempt(
                username=self.current_username,
                ip=self.current_ip,
                device_info=self.posture_checker.get_device_info(),
                success=True,
                reason="OTP verified",
            )
            # Reset failed login counter
            self.session_manager.reset_failed_logins(self.current_username)
            
            # Run device posture check
            self.mfa_status_label.config(text="Running posture and risk checks...", fg=self.WARNING_YELLOW)
            # Run device posture check
            threading.Thread(target=self._run_posture_and_risk, daemon=True).start()
        else:
            # Increment failed login counter
            fail_count = self.session_manager.increment_failed_logins(
                username=self.current_username,
                ip=self.current_ip,
                reason="Invalid OTP",
            )
            
            # Log failed attempt
            self.session_manager.log_login_attempt(
                username=self.current_username,
                ip=self.current_ip,
                device_info=self.posture_checker.get_device_info(),
                success=False,
                reason=f"Invalid OTP (attempt {fail_count}/3)",
            )
            
            self.mfa_status_label.config(text=f"✗ MFA Failed (Attempt {fail_count}/3)", fg=self.DANGER_RED)
            messagebox.showerror("MFA Failed", f"Invalid OTP. Access Denied.\n(Attempt {fail_count}/3)")
            
            # Lock account after 3 failed attempts
            if fail_count >= 3:
                self.session_manager.lock_account(
                    username=self.current_username,
                    lock_duration_minutes=15,
                    reason="Too many failed OTP attempts",
                )
                messagebox.showerror(
                    "Account Locked",
                    "Account locked for 15 minutes due to too many failed OTP attempts.\nPlease try again later.",
                )
            
            self._reset_login_form()
    
    def _run_posture_and_risk(self) -> None:
        # Device posture check
        posture_result = self.posture_checker.run_checks()
        posture_score = float(posture_result.get("posture_score", 0.0))

        # --- NEW: Geolocation + VPN/Tor check ---
        geo_result = self.risk_scorer.get_geo_vpn_risk(
            ip=self.current_ip, home_country="Pakistan"
        )
        self._latest_geo_result = dict(geo_result)
        geo_vpn_score = float(geo_result.get("risk_score", 5.0))

        # --- NEW: Failed login attempts check ---
        sessions_log_path = str(self.base_dir / "sessions_log.json")
        failed_result = self.risk_scorer.get_failed_login_risk(
            username=self.current_username, log_file=sessions_log_path
        )
        failed_login_score = float(failed_result.get("risk_score", 0.0))

        # --- NEW: Login-time behaviour pattern check ---
        current_hour = datetime.now().hour
        behavior_result = self.risk_scorer.get_behavior_pattern_risk(
            username=self.current_username,
            current_hour=current_hour,
            log_file=sessions_log_path,
        )
        behavior_score = float(behavior_result.get("risk_score", 0.0))

        # Merge geo info into posture_result for display
        posture_result["geo_vpn"] = geo_result
        posture_result["failed_logins"] = failed_result
        posture_result["behavior_pattern"] = behavior_result

        # Display posture results (including new fields)
        self.root.after(0, self._display_posture_results, posture_result)

        # Calculate risk with all inputs
        risk_result = self.risk_scorer.calculate_risk(
            posture_score=posture_score,
            login_location="known",
            login_time=datetime.now().strftime("%H:%M:%S"),
            ip_reputation=20.0,
            traffic_behavior_score=0.0,
            geo_vpn_score=geo_vpn_score,
            failed_login_score=failed_login_score,
            behavior_pattern_score=behavior_score,
        )

        risk_score = float(risk_result["risk_score"])
        risk_level = str(risk_result["risk_level"])

        # Create session
        session = self.session_manager.create_session(
            username=self.current_username,
            role=self.current_role,
            ip=self.current_ip,
            risk_score=risk_score,
            accessed_apps=[],
            status="active",
        )
        self.current_session_id = session["session_id"]
        self.session_manager.patch_session(self.current_session_id, {"device_posture_score": posture_score})
        self._log_security_event(
            "device_posture_snapshot",
            {
                "posture_score": posture_score,
                "risk_score": risk_score,
            },
        )

        # Display risk and decision
        self.root.after(0, self._display_risk_decision, risk_score, risk_level)
        self.root.after(0, lambda: self.mfa_status_label.config(text="", fg=self.FG_WHITE))

    def _set_posture_placeholder(self) -> None:
        self.posture_text.config(state="normal")
        self.posture_text.delete(1.0, tk.END)
        self.posture_text.insert(
            1.0,
            "Posture information will appear here after successful login.\n\n"
            "The right panel will show:\n"
            "- OS\n"
            "- Firewall\n"
            "- Antivirus\n"
            "- Suspicious Processes\n"
            "- Dangerous Ports\n"
            "- Device MAC\n"
            "- OS Updates\n"
            "- Network Location\n"
            "- Failed Logins\n"
            "- Login Behaviour\n"
            "- Posture Score"
        )
        self.posture_text.config(state="disabled")

    def _update_live_risk_badge(self, score: float | None) -> None:
        if score is None:
            self.live_risk_badge.config(text="Live Risk: --", bg="#7a7a7a", fg="#ffffff")
            return

        if score < 35:
            color = self.SUCCESS_GREEN
        elif score <= 70:
            color = self.WARNING_YELLOW
        else:
            color = self.DANGER_RED

        self.live_risk_badge.config(text=f"Live Risk: {score:.1f}", bg=color, fg="#ffffff")

    def _post_runtime_warning_alert(self, message: str) -> None:
        alert = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "severity": "warning",
            "message": message,
        }
        ALERTS.append(alert)
        self._refresh_alerts()
        if self.current_session_id:
            self.session_manager.log_alert(self.current_session_id, message, severity="warning")

    def _start_continuous_risk_recalculation(self) -> None:
        if self.risk_recalc_thread and self.risk_recalc_thread.is_alive():
            return

        self.stop_risk_recalc.clear()
        self.risk_recalc_thread = threading.Thread(target=self._continuous_risk_loop, daemon=True)
        self.risk_recalc_thread.start()

    def _stop_continuous_risk_recalculation(self) -> None:
        self.stop_risk_recalc.set()

    def _continuous_risk_loop(self) -> None:
        while not self.stop_risk_recalc.wait(timeout=60):
            if not self.monitoring_active or not self.current_session_id:
                break

            try:
                posture_result = self.posture_checker.run_checks()
                posture_score = float(posture_result.get("posture_score", 0.0))

                traffic_metrics = self.traffic_monitor.get_metrics()
                traffic_score = float(traffic_metrics.get("traffic_behavior_score", 0.0))

                recalc = self.risk_scorer.recalculate_runtime_risk(
                    username=self.current_username,
                    ip=self.current_ip,
                    posture_score=posture_score,
                    traffic_behavior_score=traffic_score,
                    sessions_log_path=str(self.base_dir / "sessions_log.json"),
                    login_location="known",
                )

                risk_payload = recalc.get("risk", {})
                new_risk_score = float(risk_payload.get("risk_score", 0.0))
                new_risk_level = str(risk_payload.get("risk_level", "LOW"))

                # Log every recalculation to sessions_log.json.
                if self.current_session_id:
                    self.session_manager.update_risk_score(self.current_session_id, new_risk_score)

                self.root.after(0, lambda score=new_risk_score: self._update_live_risk_badge(score))

                if new_risk_score > (self.login_time_risk_score + 15.0):
                    if not self.risk_spike_alert_active:
                        self.risk_spike_alert_active = True
                        message = (
                            f"Runtime risk increased by more than 15 points "
                            f"(login: {self.login_time_risk_score:.1f}, now: {new_risk_score:.1f})."
                        )
                        self.root.after(0, lambda msg=message: self._post_runtime_warning_alert(msg))
                else:
                    self.risk_spike_alert_active = False

                if new_risk_score > 70:
                    self.root.after(
                        0,
                        lambda score=new_risk_score: self._terminate_session_for_security(
                            f"Security Alert: Risk crossed 70 ({score:.1f}). Session terminated immediately."
                        ),
                    )
                    break

                # Step-up authentication only when risk rises into MEDIUM range.
                if (
                    new_risk_level == "MEDIUM"
                    and self.last_runtime_risk_level == "LOW"
                    and not self.step_up_in_progress
                ):
                    self.step_up_in_progress = True
                    reverified = self._run_step_up_auth_blocking()
                    self.step_up_in_progress = False
                    if not reverified:
                        break

                self.last_runtime_risk_level = new_risk_level
            except Exception as exc:
                self.root.after(
                    0,
                    lambda err=exc: self._post_runtime_warning_alert(
                        f"Runtime risk recalculation error: {err}"
                    ),
                )
                break

    def apply_role_restrictions(self, role: str) -> None:
        """Show/hide tabs and enforce per-role permissions after successful login."""
        normalized_role = (role or "").strip().lower()

        # Hide every non-dashboard tab first.
        for name, tab_id in self.role_tabs.items():
            if name != "personal_dashboard":
                self.notebook.hide(tab_id)

        allowed_tabs_by_role = {
            "soc_operator": ["personal_security_status", "alerts", "protected_resources", "active_sessions"],
            "threat_analyst": [
                "personal_security_status",
                "alerts",
                "active_sessions",
                "traffic_monitor",
                "session_history",
                "incident_reports",
                "protected_resources",
            ],
            "security_engineer": [
                "personal_security_status",
                "alerts",
                "active_sessions",
                "traffic_monitor",
                "session_history",
                "incident_reports",
                "ip_blacklist_manager",
                "policy_simulation",
                "protected_resources",
                "risk_threshold_editor",
                "device_registry",
                "audit_export",
                "system_health",
                "activity_heatmap",
            ],
            # Backward-compatible aliases
            "viewer": ["personal_security_status", "alerts", "protected_resources"],
            "analyst": [
                "personal_security_status",
                "alerts",
                "active_sessions",
                "traffic_monitor",
                "session_history",
                "incident_reports",
                "protected_resources",
            ],
            "admin": [
                "personal_security_status",
                "alerts",
                "active_sessions",
                "traffic_monitor",
                "session_history",
                "incident_reports",
                "ip_blacklist_manager",
                "policy_simulation",
                "protected_resources",
                "risk_threshold_editor",
                "device_registry",
                "audit_export",
                "system_health",
                "activity_heatmap",
            ],
        }

        for tab_name in allowed_tabs_by_role.get(normalized_role, []):
            self.notebook.add(self.role_tabs[tab_name])

        # Alerts role permissions
        if normalized_role in {"viewer", "soc_operator"}:
            self.clear_alerts_btn.config(state="disabled")
            self.ack_alert_btn.config(state="disabled")
        elif normalized_role in {"analyst", "threat_analyst"}:
            self.clear_alerts_btn.config(state="disabled")
            self.ack_alert_btn.config(state="normal")
        elif normalized_role in {"admin", "security_engineer"}:
            self.clear_alerts_btn.config(state="normal")
            self.ack_alert_btn.config(state="normal")
        else:
            self.clear_alerts_btn.config(state="disabled")
            self.ack_alert_btn.config(state="disabled")

        # Active sessions role permissions
        if normalized_role in {"analyst", "threat_analyst"}:
            self.block_session_btn.config(state="disabled")
        elif normalized_role in {"admin", "security_engineer"}:
            self.block_session_btn.config(state="normal")
        else:
            self.block_session_btn.config(state="disabled")

        self._refresh_protected_resources_access()

        advanced_roles = {"threat_analyst", "security_engineer"}
        can_use_advanced = normalized_role in advanced_roles

        if can_use_advanced:
            self.incident_report_btn.pack(side=tk.LEFT, padx=5)
            self.manual_anomaly_scan_btn.pack(side=tk.LEFT, padx=5)
            if hasattr(self, "compare_sessions_btn"):
                self.compare_sessions_btn.pack(side=tk.LEFT, padx=5)
            self.timeline_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
            if hasattr(self, "timeline_text"):
                self.timeline_text.config(state="normal")
                self.timeline_text.delete(1.0, tk.END)
                self.timeline_text.insert(1.0, "Select a session to view threat timeline.")
                self.timeline_text.config(state="disabled")
        else:
            self.incident_report_btn.pack_forget()
            self.manual_anomaly_scan_btn.pack_forget()
            if hasattr(self, "compare_sessions_btn"):
                self.compare_sessions_btn.pack_forget()
            self.timeline_frame.pack_forget()
            if hasattr(self, "timeline_text"):
                self.timeline_text.config(state="normal")
                self.timeline_text.delete(1.0, tk.END)
                self.timeline_text.insert(1.0, "Threat timeline is available for Threat Analyst and Security Engineer roles.")
                self.timeline_text.config(state="disabled")

    def _display_posture_results(self, result: dict) -> None:
        os_info      = result.get("os", {})
        fw_info      = result.get("firewall", {})
        av_info      = result.get("antivirus", {})
        susp_info    = result.get("suspicious_processes", {})
        ports_info   = result.get("dangerous_ports", {})
        mac_info     = result.get("mac_whitelist", {})
        update_info  = result.get("os_update", {})
        geo_info     = result.get("geo_vpn", {})
        failed_info  = result.get("failed_logins", {})
        behav_info   = result.get("behavior_pattern", {})
        score        = result.get("posture_score", 0)

        text  = f"OS: {os_info.get('system')} {os_info.get('release')}\n"
        text += f"Firewall: {'Active ✓' if fw_info.get('active') else 'Inactive ✗'}\n"
        text += f"Antivirus: {'Running ✓' if av_info.get('running') else 'Not Detected ✗'}\n"
        text += f"Suspicious Processes: {'None Detected ✓' if susp_info.get('passed') else 'THREAT DETECTED ✗ ' + str(susp_info.get('detected'))}\n"
        text += f"Dangerous Ports: {'All Closed ✓' if ports_info.get('passed') else 'Open Ports ✗ ' + str(ports_info.get('open_ports'))}\n"
        text += f"Device MAC: {'Approved ✓' if mac_info.get('passed') else 'Not Whitelisted ✗'} ({mac_info.get('mac', 'N/A')})\n"
        text += f"OS Updates: {'Up to Date ✓' if update_info.get('passed') else 'Outdated ✗'} ({update_info.get('detail', 'N/A')})\n"
        text += f"─────────────────────────────────\n"
        text += f"Network Location: {geo_info.get('detail', 'N/A')}\n"
        text += f"Failed Logins (24h): {failed_info.get('detail', 'N/A')}\n"
        text += f"Login Behaviour: {behav_info.get('detail', 'N/A')}\n"
        text += f"─────────────────────────────────\n"
        text += f"Posture Score: {score}/100"

        self.posture_text.config(state="normal")
        self.posture_text.delete(1.0, tk.END)
        self.posture_text.insert(1.0, text)
        self.posture_text.config(state="disabled")

    
    def _display_risk_decision(self, risk_score: float, risk_level: str) -> None:
        self.login_time_risk_score = float(risk_score)
        self.risk_spike_alert_active = False

        if risk_level == "LOW":
            if not biometric_auth.verify_fingerprint(self.current_username, "ZTNA Sentinel — Verify your identity to continue"):
                messagebox.showerror("Error", "Fingerprint verification failed. Access denied.")
                color = self.DANGER_RED
                decision = "✗ ACCESS DENIED"
                self._stop_continuous_risk_recalculation()
                self.apply_role_restrictions("guest")
                self.last_runtime_risk_level = "HIGH"
                if self.current_session_id:
                    self.session_manager.end_session(self.current_session_id, status="blocked")
                self.risk_label.config(
                    text=f"Risk: {risk_level} ({risk_score:.1f}) - {decision}",
                    foreground=color,
                )
                self._update_live_risk_badge(float(risk_score))
                return

            if biometric_auth.LAST_BIOMETRIC_STATUS == "verified":
                messagebox.showinfo("Success", "Fingerprint verified successfully")
            color = self.SUCCESS_GREEN
            decision = "✓ ACCESS GRANTED"
            # Start monitoring
            self.monitoring_active = True
            self._start_session_monitoring()
            self._start_continuous_risk_recalculation()
            self.logout_handler.start()
            self.logout_btn.pack(side=tk.BOTTOM, pady=10)
            self.apply_role_restrictions(self.current_role)
            self._update_personal_security_status()
            self.last_runtime_risk_level = "LOW"
        elif risk_level == "MEDIUM":
            if not biometric_auth.verify_fingerprint(self.current_username, "ZTNA Sentinel — Verify your identity to continue"):
                messagebox.showerror("Error", "Fingerprint verification failed. Access denied.")
                color = self.DANGER_RED
                decision = "✗ ACCESS DENIED"
                self._stop_continuous_risk_recalculation()
                self.apply_role_restrictions("guest")
                self.last_runtime_risk_level = "HIGH"
                if self.current_session_id:
                    self.session_manager.end_session(self.current_session_id, status="blocked")
                self.risk_label.config(
                    text=f"Risk: {risk_level} ({risk_score:.1f}) - {decision}",
                    foreground=color,
                )
                self._update_live_risk_badge(float(risk_score))
                return

            if biometric_auth.LAST_BIOMETRIC_STATUS == "verified":
                messagebox.showinfo("Success", "Fingerprint verified successfully")
            color = self.WARNING_YELLOW
            decision = "⚠ ACCESS GRANTED (Extra MFA may be required)"
            self.monitoring_active = True
            self._start_session_monitoring()
            self._start_continuous_risk_recalculation()
            self.logout_handler.start()
            self.logout_btn.pack(side=tk.BOTTOM, pady=10)
            self.apply_role_restrictions(self.current_role)
            self._update_personal_security_status()
            self.last_runtime_risk_level = "MEDIUM"
        else:
            color = self.DANGER_RED
            decision = "✗ ACCESS DENIED"
            self._stop_continuous_risk_recalculation()
            self.apply_role_restrictions("guest")
            self.last_runtime_risk_level = "HIGH"
            if self.current_session_id:
                self.session_manager.end_session(self.current_session_id, status="blocked")
        
        self.risk_label.config(
            text=f"Risk: {risk_level} ({risk_score:.1f}) - {decision}",
            foreground=color
        )
        self._update_live_risk_badge(float(risk_score))
    
    def _reset_login_form(self) -> None:
        self.login_btn.config(state="normal")
        self.verify_otp_btn.config(state="normal")
        self.otp_frame.grid_remove()
        self.otp_entry.delete(0, tk.END)
        self.mfa_status_label.config(text="", fg="#222222")
    
    def _start_session_monitoring(self) -> None:
        """Start background anomaly detection and traffic monitoring."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
        
        self.stop_monitoring.clear()
        self.step_up_in_progress = False
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

        # Traffic capture is user-controlled from the Traffic Monitor tab.
    
    def _monitoring_loop(self) -> None:
        """Background loop for anomaly detection."""
        while not self.stop_monitoring.is_set() and self.monitoring_active:
            if not self.current_session_id:
                break
            
            time.sleep(30)  # Check every 30 seconds
            
            # Get traffic metrics
            metrics = self.traffic_monitor.get_metrics()
            traffic_score = float(metrics.get("traffic_behavior_score", 0.0))

            if not metrics.get("capture_running") and traffic_score <= 0.0:
                continue
            
            # Run anomaly detection
            session_summary = {
                "user": self.current_username,
                "ip": self.current_ip,
                "role": self.current_role,
                "risk_score": traffic_score,
                "traffic_flags": metrics.get("suspicious_patterns", {}),
                "accessed_apps": [],
                "login_time": datetime.now().strftime("%H:%M:%S"),
                "login_location": "known",
            }
            
            anomaly = self.anomaly_detector.analyze_session(session_summary)
            self._log_security_event(
                "traffic_anomaly_scan",
                {
                    "is_anomalous": bool(anomaly.get("is_anomalous")),
                    "decision": str(anomaly.get("recommended_action", "allow")),
                    "reason": str(anomaly.get("reason", "")),
                    "traffic_flags": metrics.get("suspicious_patterns", {}),
                    "traffic_behavior_score": traffic_score,
                },
            )
            
            if anomaly.get("is_anomalous"):
                self.threat_handler.decide_and_respond(
                    session_id=self.current_session_id,
                    risk_level="HIGH",
                    is_anomalous=True,
                    ip_address=self.current_ip,
                )
                self.session_manager.end_session(self.current_session_id, status="blocked")
                self.monitoring_active = False
                self._stop_continuous_risk_recalculation()
                break

    def _run_step_up_auth_blocking(self) -> bool:
        """Request MFA step-up on the GUI thread and wait for outcome from the monitor thread."""
        if not self.current_email:
            self.root.after(0, lambda: self._terminate_session_for_security(
                "Security Alert: Missing registered email for re-verification. Session terminated."
            ))
            return False

        done = threading.Event()
        result = {"approved": False}
        self.root.after(0, lambda: self._show_step_up_popup(done, result))

        while not done.is_set() and self.monitoring_active and not self.stop_monitoring.is_set():
            time.sleep(0.15)

        return bool(result.get("approved", False))

    def _show_step_up_popup(self, done_event: threading.Event, result: dict[str, bool]) -> None:
        """Show blocking re-verification popup with OTP and 60-second countdown."""
        # Generate and send fresh OTP for step-up authentication.
        self.mfa_handler.send_otp(self.current_username, self.current_email)

        popup = tk.Toplevel(self.root)
        popup.title("Step-up Authentication Required")
        popup.geometry("540x270")
        popup.configure(bg="#ffffff")
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.grab_set()
        popup.protocol("WM_DELETE_WINDOW", lambda: None)

        tk.Label(
            popup,
            text="Security Alert: Your risk level has increased. Re-verification required.",
            bg="#ffffff",
            fg="#c53030",
            font=("Arial", 12, "bold"),
            wraplength=500,
            justify="left",
        ).pack(padx=18, pady=(18, 14), anchor="w")

        tk.Label(
            popup,
            text=f"A fresh OTP has been sent to {self.current_email}",
            bg="#ffffff",
            fg="#333333",
            font=("Arial", 10),
        ).pack(padx=18, pady=(0, 10), anchor="w")

        otp_row = tk.Frame(popup, bg="#ffffff")
        otp_row.pack(fill="x", padx=18, pady=(0, 8))

        tk.Label(otp_row, text="Enter OTP:", bg="#ffffff", fg="#222222", font=("Arial", 10)).pack(side="left")
        otp_entry = tk.Entry(otp_row, width=20, font=("Arial", 10), bg="#ffffff", fg="#000000", relief="solid", bd=1)
        otp_entry.pack(side="left", padx=(8, 0))
        otp_entry.focus_set()

        timer_label = tk.Label(
            popup,
            text="Time remaining: 60s",
            bg="#ffffff",
            fg="#d69e2e",
            font=("Arial", 11, "bold"),
        )
        timer_label.pack(padx=18, pady=(0, 10), anchor="w")

        def approve_and_close() -> None:
            if done_event.is_set():
                return
            result["approved"] = True
            self._log_security_event("reverification_success", {
                "message": "Step-up authentication successful.",
                "role": self.current_role,
                "ip": self.current_ip,
            })
            done_event.set()
            popup.grab_release()
            popup.destroy()

        def fail_and_terminate(reason: str) -> None:
            if done_event.is_set():
                return
            result["approved"] = False
            self._log_security_event("security_incident", {
                "message": reason,
                "role": self.current_role,
                "ip": self.current_ip,
            })
            done_event.set()
            popup.grab_release()
            popup.destroy()
            self._terminate_session_for_security(reason)

        def verify_now() -> None:
            entered = otp_entry.get().strip()
            if self.mfa_handler.verify_otp(self.current_username, entered):
                approve_and_close()
            else:
                fail_and_terminate("Security Incident: Invalid OTP during step-up verification.")

        tk.Button(
            popup,
            text="Verify OTP",
            bg="#2f855a",
            fg="#ffffff",
            font=("Arial", 10, "bold"),
            relief="flat",
            cursor="hand2",
            command=verify_now,
        ).pack(padx=18, pady=(2, 0), anchor="w")

        remaining = {"seconds": 60}

        def tick() -> None:
            if done_event.is_set() or not popup.winfo_exists():
                return
            remaining["seconds"] -= 1
            timer_label.config(text=f"Time remaining: {remaining['seconds']}s")
            if remaining["seconds"] <= 0:
                fail_and_terminate("Security Incident: Step-up OTP timer expired.")
                return
            popup.after(1000, tick)

        popup.after(1000, tick)

    def _log_security_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Log custom security events to sessions_log.json."""
        if not self.current_session_id:
            return
        session = self.session_manager.sessions.get(self.current_session_id)
        if not session:
            return
        self.session_manager.append_session_event(self.current_session_id, event_type, details)

    def _terminate_session_for_security(self, reason: str) -> None:
        """Terminate active session and return to login for security enforcement."""
        self._stop_continuous_risk_recalculation()
        self.traffic_monitor.stop()

        if self._personal_status_after_id:
            try:
                self.root.after_cancel(self._personal_status_after_id)
            except tk.TclError:
                pass
            self._personal_status_after_id = None

        if self.current_session_id:
            self._log_security_event("security_incident", {
                "message": reason,
                "role": self.current_role,
                "ip": self.current_ip,
            })
            self.session_manager.log_alert(self.current_session_id, reason, severity="high")
            self.session_manager.end_session(self.current_session_id, status="blocked")
            self.current_session_id = None

        self.monitoring_active = False
        self.stop_monitoring.set()
        self.logout_handler.cancel()

        self._reset_login_form()
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.current_email = ""
        self.risk_label.config(text="")
        self._update_live_risk_badge(None)
        self._set_posture_placeholder()
        self.apply_role_restrictions("guest")
        self.logout_btn.pack_forget()

        self.notebook.select(self.login_tab)
        messagebox.showerror("Security Incident", reason)

    def _soc_registrar_override_click(self) -> None:
        """SOC / blue team simulated write to registrar data — always audited and alerted."""
        if not self.rbac_manager.is_staff_role(self.current_role):
            messagebox.showwarning("Role", "Sign in as SOC or blue-team staff on the main login first.")
            return
        if not self.current_session_id:
            messagebox.showwarning("Session", "A staff session on the main window is required.")
            return
        tgt = self.soc_registrar_target.get().strip().lower()
        note = self.soc_registrar_note_widget.get("1.0", tk.END).strip()
        if not tgt or not note:
            messagebox.showwarning("Missing", "Target student username and note are required.")
            return
        if self._student_contains_sqli(note):
            messagebox.showerror("Blocked", "Note rejected as possible SQL injection.")
            return
        self._expect_sessions_log_mutation = True
        aud = self.session_manager.portal_database_mutation(
            actor_role=self.current_role,
            actor_username=self.current_username or "staff",
            actor_session_id=str(self.current_session_id),
            operation="INSERT",
            entity="registrar_override",
            entity_key=tgt,
            payload={"note": note},
            target_username=tgt,
        )
        self._notify_portal_database_change(aud)
        self.session_manager.append_session_event(
            str(self.current_session_id),
            "soc_registrar_override",
            {"target": tgt, "audit_id": aud.get("id"), "summary": "SOC registrar simulated DB write"},
        )
        self._expect_sessions_log_mutation = False
        self._refresh_alerts()
        self._refresh_sessions()
        messagebox.showinfo(
            "Registrar",
            "Override stored. Alerts were raised; student session (if active) received a portal_db_change event.",
        )
    
    # ================== TAB 2: ACTIVE SESSIONS ==================
    
    def _create_sessions_tab(self) -> None:
        style = ttk.Style()
        style.theme_use('default')
        style.configure(
            "Sessions.Treeview",
            background="white",
            foreground="black",
            rowheight=28,
            fieldbackground="white",
            font=("Arial", 9),
        )
        style.configure(
            "Sessions.Treeview.Heading",
            background="#FFB300",
            foreground="black",
            font=("Arial", 9, "bold"),
        )
        style.map(
            "Sessions.Treeview",
            background=[("selected", "#0078d7")],
            foreground=[("selected", "white")],
        )

        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="📊 Active Sessions")
        
        # Toolbar
        toolbar = ttk.Frame(tab, style="Dark.TFrame")
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        self.refresh_sessions_btn = ttk.Button(toolbar, text="Refresh", 
              command=self._refresh_sessions)
        self.refresh_sessions_btn.pack(side=tk.LEFT, padx=5)
        self.sessions_debug_label = ttk.Label(
            toolbar,
            text="Sessions in file: 0 | Showing: 0",
            style="Dark.TLabel",
        )
        self.sessions_debug_label.pack(side=tk.LEFT, padx=12)
        self.block_session_btn = ttk.Button(toolbar, text="Block Selected", 
              command=self._block_selected_session)
        self.block_session_btn.pack(side=tk.LEFT, padx=5)
        self.incident_report_btn = ttk.Button(
            toolbar,
            text="Generate Incident Report",
            command=self._generate_incident_report,
        )
        self.incident_report_btn.pack(side=tk.LEFT, padx=5)
        
        # Sessions table
        columns = ("Session_ID", "Username", "Role", "IP", "Risk", "Status", "Time")
        self.sessions_tree = ttk.Treeview(tab, columns=columns, show="headings", height=20, style="Sessions.Treeview")
        self.sessions_tree.tag_configure("oddrow", background="#f9f9f9", foreground="black")
        self.sessions_tree.tag_configure("evenrow", background="white", foreground="black")
        
        self.sessions_tree.heading("Session_ID", text="Session ID")
        self.sessions_tree.heading("Username", text="Username")
        self.sessions_tree.heading("Role", text="Role")
        self.sessions_tree.heading("IP", text="IP Address")
        self.sessions_tree.heading("Risk", text="Risk")
        self.sessions_tree.heading("Status", text="Status")
        self.sessions_tree.heading("Time", text="Time")
        
        self.sessions_tree.column("Session_ID", width=250)
        self.sessions_tree.column("Username", width=120)
        self.sessions_tree.column("Role", width=100)
        self.sessions_tree.column("IP", width=120)
        self.sessions_tree.column("Risk", width=100)
        self.sessions_tree.column("Status", width=100)
        self.sessions_tree.column("Time", width=180)
        
        scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.sessions_tree.yview)
        self.sessions_tree.configure(yscroll=scrollbar.set)
        
        table_frame = ttk.Frame(tab, style="Dark.TFrame")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))

        self.sessions_tree.pack(in_=table_frame, side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8), pady=0)
        scrollbar.pack(in_=table_frame, side=tk.RIGHT, fill=tk.Y, padx=(0, 0), pady=0)

        details_frame = ttk.LabelFrame(tab, text="Selected Session Details", style="Dark.TFrame", padding=10)
        details_frame.pack(fill=tk.X, padx=10, pady=(10, 10))

        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL)
        self.session_details_text = tk.Text(
            details_frame,
            bg=self.BG_MEDIUM,
            fg=self.FG_WHITE,
            font=("Courier", 9),
            height=8,
            yscrollcommand=details_scroll.set,
            wrap="word",
        )
        details_scroll.config(command=self.session_details_text.yview)
        self.session_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.session_details_text.insert(tk.END, "Select a session to view posture, risk, and event details.")
        self.session_details_text.config(state="disabled")

        soc_fr = ttk.LabelFrame(
            tab,
            text="Simulated registrar database — SOC / blue team writes (audited + alerted)",
            style="Dark.TFrame",
            padding=8,
        )
        soc_fr.pack(fill=tk.X, padx=10, pady=(0, 10))
        r1 = ttk.Frame(soc_fr, style="Dark.TFrame")
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="Target student username:", style="Dark.TLabel").pack(side=tk.LEFT)
        self.soc_registrar_target = tk.Entry(r1, width=32, font=("Arial", 10))
        self.soc_registrar_target.pack(side=tk.LEFT, padx=8)

        def _fill_soc_target_from_tree() -> None:
            sel = self.sessions_tree.selection()
            if not sel:
                messagebox.showinfo("Sessions", "Select an active session row first.")
                return
            vals = self.sessions_tree.item(sel[0], "values")
            if len(vals) >= 2:
                self.soc_registrar_target.delete(0, tk.END)
                self.soc_registrar_target.insert(0, str(vals[1]))

        ttk.Button(r1, text="Use selected session username", command=_fill_soc_target_from_tree).pack(side=tk.LEFT, padx=6)
        ttk.Label(soc_fr, text="Registrar / compliance note (stored in sessions_log.json):", style="Dark.TLabel").pack(anchor="w", pady=(6, 0))
        self.soc_registrar_note_widget = tk.Text(
            soc_fr,
            height=3,
            width=100,
            bg=self.BG_MEDIUM,
            fg=self.FG_WHITE,
            font=("Arial", 10),
        )
        self.soc_registrar_note_widget.pack(fill=tk.X, pady=4)
        ttk.Button(soc_fr, text="Apply override (generates alerts + DB audit)", command=self._soc_registrar_override_click).pack(anchor="w", pady=4)

        self._selected_soc_session_id: str | None = None
        self.sessions_tree.bind("<<TreeviewSelect>>", self._on_sessions_selection_change)
        # Add live activity feed for SOC in this tab
        feed_frame = ttk.LabelFrame(tab, text="Live Activity Feed (SOC)", style="Dark.TFrame", padding=8)
        feed_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        scroll = ttk.Scrollbar(feed_frame, orient=tk.VERTICAL)
        self.live_activity_text = tk.Text(feed_frame, bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                         font=("Courier", 9), yscrollcommand=scroll.set, height=8, wrap="word")
        scroll.config(command=self.live_activity_text.yview)
        self.live_activity_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Auto-refresh feed every 10s when tab is visible
        self._feed_refresh_after_id = None
        self._start_feed_auto_refresh()
        return tab
    
    def _refresh_sessions(self) -> None:
        """Reload sessions and display any session that has a username.

        This method intentionally avoids debug prints and filters solely on
        the presence of a `username` field so student sessions are visible.
        """
        sessions_in_file_count = 0
        try:
            with self.sessions_log.open("r", encoding="utf-8") as f:
                raw_data = json.load(f)
            sessions_in_file_count = len(raw_data) if isinstance(raw_data, dict) else 0
        except Exception:
            pass

        self.session_manager.reload_from_disk()
        selected_sid = self._selected_soc_session_id
        sid_to_item: dict[str, str] = {}
        rows_shown = 0

        # Clear existing rows
        for item in self.sessions_tree.get_children():
            self.sessions_tree.delete(item)

        # Show any session that has a username (skip metadata keys), newest first.
        session_rows = [
            (sid, session)
            for sid, session in self.session_manager.sessions.items()
            if isinstance(session, dict) and not sid.startswith("__") and session.get("username")
        ]

        def _session_sort_key(item: tuple[str, dict[str, Any]]) -> float:
            raw_login_time = str(item[1].get("login_time", ""))
            try:
                return datetime.fromisoformat(raw_login_time.replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0

        for sid, session in sorted(session_rows, key=_session_sort_key, reverse=True):

            try:
                risk_score = float(session.get("risk_score", 0) or 0.0)
            except (TypeError, ValueError):
                risk_score = 0.0

            values = (
                sid,
                session.get("username", ""),
                session.get("role", ""),
                session.get("ip", ""),
                f"{risk_score:.1f}",
                session.get("status", ""),
                str(session.get("login_time", ""))[:19],
            )

            tags = ("oddrow" if rows_shown % 2 == 0 else "evenrow",)
            try:
                item = self.sessions_tree.insert("", tk.END, values=values, tags=tags)
            except Exception:
                # Skip problematic rows silently to keep UI responsive
                continue

            sid_to_item[str(sid)] = item
            rows_shown += 1

        if selected_sid and selected_sid in sid_to_item:
            item = sid_to_item[selected_sid]
            self.sessions_tree.selection_set(item)
            self.sessions_tree.focus(item)

        if hasattr(self, "sessions_debug_label"):
            self.sessions_debug_label.config(
                text=f"Sessions in file: {sessions_in_file_count} | Showing: {rows_shown}"
            )

        self.sessions_tree.update()
        self.sessions_tree.yview_moveto(0)
        self._show_selected_session_details()
        self.sessions_tree.update()
        self.sessions_tree.yview_moveto(0)

        try:
            self._refresh_live_activity_feed()
        except Exception:
            pass

    def _on_sessions_selection_change(self, _event: tk.Event | None = None) -> None:
        selection = self.sessions_tree.selection()
        if selection:
            values = self.sessions_tree.item(selection[0], "values")
            self._selected_soc_session_id = str(values[0]) if values else None
        else:
            self._selected_soc_session_id = None
        self._show_selected_session_details()

    def _start_feed_auto_refresh(self) -> None:
        if self._feed_refresh_after_id:
            try:
                self.root.after_cancel(self._feed_refresh_after_id)
            except Exception:
                pass
        def _tick() -> None:
            try:
                self._refresh_live_activity_feed()
            finally:
                self._feed_refresh_after_id = self.root.after(10000, _tick)
        self._feed_refresh_after_id = self.root.after(500, _tick)

    def _refresh_live_activity_feed(self) -> None:
        if not hasattr(self, "live_activity_text"):
            return
        self.session_manager.reload_from_disk()
        rows = self.session_manager.list_recent_activity(limit=60)
        self.live_activity_text.config(state="normal")
        self.live_activity_text.delete(1.0, tk.END)
        if not rows:
            self.live_activity_text.insert(tk.END, "No recent student portal activity.")
        else:
            for r in rows[:60]:
                ts = str(r.get("timestamp", ""))[:19]
                user = r.get("username", "")
                sid = r.get("session_id", "")
                act = r.get("action_type", "")
                summ = r.get("summary", "")
                line = f"{ts} | {user} | {sid[:8]} | {act}"
                if summ:
                    line += f" | {summ}"
                self.live_activity_text.insert(tk.END, line + "\n")
        self.live_activity_text.config(state="disabled")

    def _show_selected_session_details(self, _event: tk.Event | None = None) -> None:
        if not hasattr(self, "session_details_text"):
            return

        selection = self.sessions_tree.selection()
        if not selection:
            detail_text = "Select a session to view posture, risk, and event details."
        else:
            item = selection[0]
            values = self.sessions_tree.item(item, "values")
            session_id = str(values[0]) if values else ""
            self.session_manager.reload_from_disk()
            session = self.session_manager.sessions.get(session_id, {})
            events = list(session.get("events", [])) if isinstance(session, dict) else []
            feed = list(session.get("activity_feed") or []) if isinstance(session, dict) else []

            event_lines = []
            for event in events:
                timestamp = str(event.get("timestamp", ""))[:19]
                event_type = str(event.get("event_type", ""))
                details = event.get("details", {})
                event_lines.append(f"- {timestamp} | {event_type} | {details}")

            feed_lines: list[str] = []
            for row in feed:
                if isinstance(row, dict):
                    ts = str(row.get("timestamp", ""))[:19]
                    act = str(row.get("action_type", ""))
                    summ = str(row.get("summary", "") or "")
                    feed_lines.append(f"- {ts} | {act}" + (f" | {summ}" if summ else ""))
                else:
                    feed_lines.append(f"- {row}")

            detail_blocks = [
                f"Session ID: {session_id}",
                f"Username: {session.get('username', 'N/A')}",
                f"Login Time: {str(session.get('login_time', 'N/A'))[:19]}",
                f"IP Address: {session.get('ip', 'N/A')}",
                f"Risk Score: {float(session.get('risk_score', 0.0)):.1f}",
                f"Role: {session.get('role', 'N/A')}",
                f"Device Posture Score: {session.get('device_posture_score', 'N/A')}",
                f"Status: {session.get('status', 'N/A')}",
                f"Accessed Apps: {', '.join(session.get('accessed_apps', [])) or 'None'}",
                "",
                "Session Events:",
                *(event_lines or ["- No events recorded."]),
            ]
            if str(session.get("role", "")).lower() == "student" or feed_lines:
                detail_blocks.extend([
                    "",
                    "Student Portal Activity (latest):",
                    *(feed_lines or ["- No portal actions logged yet."]),
                ])
            db_lines: list[str] = []
            uname = str(session.get("username", "")).strip()
            if uname:
                for row in self.session_manager.list_portal_audit_for_username(uname, limit=10):
                    db_lines.append(
                        f"- {str(row.get('timestamp', ''))[:19]} | {row.get('entity')} | "
                        f"by {row.get('actor_username')} ({row.get('actor_role')})"
                    )
            if db_lines:
                detail_blocks.extend(["", "Simulated portal DB audit (this user):", *db_lines])

            detail_text = "\n".join(detail_blocks)

        self.session_details_text.config(state="normal")
        self.session_details_text.delete(1.0, tk.END)
        self.session_details_text.insert(tk.END, detail_text)
        self.session_details_text.config(state="disabled")

    def _refresh_incident_reports(self) -> None:
        """Load stored incident reports from sessions_log.json and display them."""
        try:
            self.session_manager.reload_from_disk()
            reports = self.session_manager.list_incident_reports(limit=100)
            self._incident_report_rows = {}

            for item in self.incident_reports_tree.get_children():
                self.incident_reports_tree.delete(item)

            if not reports:
                self._set_incident_report_detail(
                    "No incident reports available yet.\n\nSelect a session in Active Sessions and click Generate Incident Report."
                )
                return

            for rec in reports:
                row_id = self.incident_reports_tree.insert(
                    "",
                    tk.END,
                    values=(
                        str(rec.get("timestamp", ""))[:19],
                        str(rec.get("session_id", "")),
                        str(rec.get("author", "")),
                    ),
                )
                self._incident_report_rows[row_id] = rec

            first = self.incident_reports_tree.get_children()
            if first:
                self.incident_reports_tree.selection_set(first[0])
                self._show_selected_incident_report()
        except Exception:
            pass

    def _export_selected_incident_report(self) -> None:
        # Export the selected incident report, or the most recent one if nothing is selected.
        try:
            selected = self._get_selected_incident_report_record()
            if selected is None:
                reps = self.session_manager.list_incident_reports(limit=1)
                selected = reps[0] if reps else None
            if selected is None:
                messagebox.showinfo("No Reports", "No incident reports available to export.")
                return
            sid = str(selected.get("session_id", "unknown"))
            report_text = str(selected.get("report", ""))
            self._save_report_to_desktop(report_text, sid)
        except Exception as exc:
            messagebox.showerror("Error", f"Export failed: {exc}")

    def _get_selected_incident_report_record(self) -> dict[str, Any] | None:
        selection = self.incident_reports_tree.selection() if hasattr(self, "incident_reports_tree") else ()
        if not selection:
            return None
        return self._incident_report_rows.get(selection[0])

    def _set_incident_report_detail(self, text: str) -> None:
        if not hasattr(self, "incident_report_detail_text"):
            return
        self.incident_report_detail_text.config(state="normal")
        self.incident_report_detail_text.delete(1.0, tk.END)
        self.incident_report_detail_text.insert(tk.END, text)
        self.incident_report_detail_text.config(state="disabled")

    def _show_selected_incident_report(self, _event: tk.Event | None = None) -> None:
        record = self._get_selected_incident_report_record()
        if not record:
            self._set_incident_report_detail("No incident report selected.")
            return

        report_text = str(record.get("report", ""))
        header = [
            f"Report ID: {record.get('id', 'N/A')}",
            f"Timestamp: {record.get('timestamp', 'N/A')}",
            f"Session ID: {record.get('session_id', 'N/A')}",
            f"Author: {record.get('author', 'N/A')}",
            "",
            report_text or "No report text stored.",
        ]
        self._set_incident_report_detail("\n".join(header))
    
    def _calculate_risk_level(self, score: float) -> str:
        if score < 35:
            return "LOW"
        elif score < 70:
            return "MEDIUM"
        return "HIGH"
    
    def _block_selected_session(self) -> None:
        selection = self.sessions_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a session to block.")
            return
        
        item = selection[0]
        values = self.sessions_tree.item(item, "values")
        session_id = values[0]
        
        if messagebox.askyesno("Confirm", f"Block session {session_id}?"):
            self.session_manager.end_session(session_id, status="blocked")
            session = self.session_manager.sessions.get(session_id, {})
            ip = session.get("ip", "")
            if ip:
                self.threat_handler.block_ip(ip, "Manual GUI block")
            
            self._refresh_sessions()
            messagebox.showinfo("Success", "Session blocked successfully.")
    
    # ================== TAB 3: ALERTS & THREATS ==================
    
    def _create_alerts_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.alerts_tab_index = self.notebook.index("end") - 1  # Will be updated after add
        self.notebook.add(tab, text="⚠️ Alerts")
        
        # Toolbar with filters
        toolbar = ttk.Frame(tab, style="Dark.TFrame")
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        # Filter buttons
        self.filter_var = tk.StringVar(value="all")
        
        ttk.Label(toolbar, text="Filter:", style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(toolbar, text="All", variable=self.filter_var, value="all", 
                       command=self._refresh_alerts).pack(side=tk.LEFT, padx=3)
        ttk.Radiobutton(toolbar, text="Unacknowledged", variable=self.filter_var, value="unack",
                       command=self._refresh_alerts).pack(side=tk.LEFT, padx=3)
        ttk.Radiobutton(toolbar, text="Critical", variable=self.filter_var, value="critical",
                       command=self._refresh_alerts).pack(side=tk.LEFT, padx=3)
        
        # Action buttons
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        self.ack_alert_btn = ttk.Button(toolbar, text="✓ Acknowledge", 
              command=self._acknowledge_selected_alert)
        self.ack_alert_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_alerts_btn = ttk.Button(toolbar, text="🗑 Clear All", 
              command=self._clear_alerts)
        self.clear_alerts_btn.pack(side=tk.LEFT, padx=5)
        
        # Counter on right
        self.alert_count_label = ttk.Label(toolbar, text="Alerts: 0 | Unacknowledged: 0")
        self.alert_count_label.pack(side=tk.RIGHT, padx=10)
        
        # Alerts treeview with columns
        list_frame = ttk.Frame(tab, style="Dark.TFrame")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create Treeview for better alert display
        self.alerts_tree = ttk.Treeview(list_frame, columns=("Time", "Severity", "Status", "Message"), 
                                        height=20, show="tree headings")
        
        self.alerts_tree.column("#0", width=0, stretch=tk.NO)
        self.alerts_tree.column("Time", anchor=tk.W, width=150)
        self.alerts_tree.column("Severity", anchor=tk.CENTER, width=80)
        self.alerts_tree.column("Status", anchor=tk.CENTER, width=100)
        self.alerts_tree.column("Message", anchor=tk.W, width=300)
        
        self.alerts_tree.heading("Time", text="Time")
        self.alerts_tree.heading("Severity", text="Severity")
        self.alerts_tree.heading("Status", text="Status")
        self.alerts_tree.heading("Message", text="Message")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        return tab
    
    def _refresh_alerts(self) -> None:
        self._merge_persisted_alerts_into_memory()
        self._sync_student_login_alerts_from_sessions()

        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Apply filter
        filter_type = self.filter_var.get()
        filtered_alerts = []
        
        for alert in reversed(ALERTS[-100:]):  # Show last 100 alerts
            if filter_type == "unack" and alert.get("acknowledged", False):
                continue
            if filter_type == "critical" and alert.get("severity") != "CRITICAL":
                continue
            filtered_alerts.append(alert)
        
        # Add to treeview
        from threat_response.response_handler import SEVERITY_COLORS
        
        for alert in filtered_alerts:
            timestamp = alert.get("timestamp", "")[:19]  # Trim to YYYY-MM-DD HH:MM:SS
            severity = alert.get("severity", "INFO")
            message = alert.get("message", "")
            acknowledged = alert.get("acknowledged", False)
            status = "✓ Ack" if acknowledged else "⏳ New"
            
            item_id = self.alerts_tree.insert("", "end", values=(timestamp, severity, status, message))
            
            # Color code by severity
            color = SEVERITY_COLORS.get(severity, "#2f855a")
            self.alerts_tree.item(item_id, tags=(severity,))
            self.alerts_tree.tag_configure(severity, foreground=color)
        
        # Update counters and badge
        total_alerts = len(ALERTS)
        unack_count = sum(1 for a in ALERTS if not a.get("acknowledged", False))
        self.alert_count_label.config(text=f"Alerts: {total_alerts} | Unacknowledged: {unack_count}")
        
        # Update tab label with badge
        self._update_alerts_badge(unack_count)

    def _sync_student_login_alerts_from_sessions(self) -> None:
        """Mirror persisted student login events into the shared alerts list."""
        # Student login events are already logged when they happen.
        # Do not re-inject historical logins into the live alert feed on every refresh.
        return
    
    def _update_alerts_badge(self, unack_count: int) -> None:
        """Update the alerts tab label with unacknowledged count badge."""
        if unack_count > 0:
            badge_text = f"⚠️ Alerts 🚨 ({unack_count})"
        else:
            badge_text = "⚠️ Alerts"
        
        try:
            # Use the actual alerts tab widget, because tab indices change with role-based hide/show.
            self.notebook.tab(self.alerts_tab, text=badge_text)
        except (tk.TclError, IndexError):
            pass  # Tab may not exist yet
    
    def _clear_alerts(self) -> None:
        if messagebox.askyesno("Confirm", "Clear all alerts?"):
            ALERTS.clear()
            self._refresh_alerts()

    def _acknowledge_selected_alert(self) -> None:
        selection = self.alerts_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No alert selected.")
            return
        
        # Get the selected alert index
        selected_item = selection[0]
        item_index = self.alerts_tree.index(selected_item)
        
        # Find corresponding alert in reversed list
        filtered_count = 0
        for idx, alert in enumerate(reversed(ALERTS[-100:])):
            if self.filter_var.get() == "unack" and alert.get("acknowledged", False):
                continue
            if self.filter_var.get() == "critical" and alert.get("severity") != "CRITICAL":
                continue
            
            if filtered_count == item_index:
                # Found the alert
                real_index = len(ALERTS) - 1 - idx
                ALERTS[real_index]["acknowledged"] = True
                ALERTS[real_index]["acknowledged_by"] = self.current_username or "system"
                ALERTS[real_index]["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
                
                messagebox.showinfo("Success", f"Alert acknowledged by {ALERTS[real_index]['acknowledged_by']}")
                self._refresh_alerts()
                return
            
            filtered_count += 1
        
        messagebox.showerror("Error", "Could not find selected alert.")
        if not selection:
            messagebox.showwarning("Warning", "Please select an alert to acknowledge.")
            return

        index = selection[0]
        current_text = self.alerts_listbox.get(index)
        if not current_text.startswith("[ACK] "):
            self.alerts_listbox.delete(index)
            self.alerts_listbox.insert(index, f"[ACK] {current_text}")
            self.alerts_listbox.itemconfig(index, fg=self.SUCCESS_GREEN)
    
    # ================== TAB 4: TRAFFIC MONITOR ==================
    
    def _create_traffic_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="📡 Traffic Monitor")
        
        # Controls
        controls = ttk.Frame(tab, style="Dark.TFrame")
        controls.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_traffic_btn = ttk.Button(controls, text="Start Monitoring", 
                                            command=self._start_traffic_capture)
        self.start_traffic_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_traffic_btn = ttk.Button(controls, text="Stop Monitoring", 
                                           command=self._stop_traffic_capture, state="disabled")
        self.stop_traffic_btn.pack(side=tk.LEFT, padx=5)

        self.manual_anomaly_scan_btn = ttk.Button(
            controls,
            text="Manual Anomaly Scan",
            command=self._run_manual_anomaly_scan,
        )
        self.manual_anomaly_scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(tab, text="Traffic Statistics", 
                                     style="Dark.TFrame", padding=15)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.pps_label = ttk.Label(stats_frame, text="Packets/sec: 0")
        self.pps_label.grid(row=0, column=0, padx=20, pady=5, sticky="w")
        
        self.data_label = ttk.Label(stats_frame, text="Data Transferred: 0 MB")
        self.data_label.grid(row=0, column=1, padx=20, pady=5, sticky="w")
        
        self.suspicious_label = ttk.Label(stats_frame, text="Suspicious Flags: None")
        self.suspicious_label.grid(row=1, column=0, columnspan=2, padx=20, pady=5, sticky="w")
        
        # Packet log
        log_frame = ttk.LabelFrame(tab, text="Recent Packets (Last 20)", 
                                   style="Dark.TFrame", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL)
        self.traffic_text = tk.Text(log_frame, bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                                    font=("Courier", 8), yscrollcommand=scrollbar.set,
                                    state="disabled")
        scrollbar.config(command=self.traffic_text.yview)
        
        self.traffic_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        return tab
    
    def _start_traffic_capture(self) -> None:
        self.traffic_monitor.start()
        self.start_traffic_btn.config(state="disabled")
        self.stop_traffic_btn.config(state="normal")
        messagebox.showinfo("Started", "Traffic monitoring started.\n\n"
                          "Note: May require Administrator privileges on Windows.")
    
    def _stop_traffic_capture(self) -> None:
        self.traffic_monitor.stop()
        self.start_traffic_btn.config(state="normal")
        self.stop_traffic_btn.config(state="disabled")
        messagebox.showinfo("Stopped", "Traffic monitoring stopped.")
    
    def _update_traffic_stats(self) -> None:
        metrics = self.traffic_monitor.get_metrics()
        capture_running = bool(metrics.get("capture_running"))

        if not capture_running:
            self.pps_label.config(text="Packets/sec: 0")
            self.data_label.config(text="Data Transferred: 0.00 MB")
            self.suspicious_label.config(text="Suspicious Flags: None")
            self.traffic_text.config(state="normal")
            self.traffic_text.delete(1.0, tk.END)
            self.traffic_text.insert(tk.END, "Traffic capture is stopped. Click Start Monitoring to begin capture.")
            self.traffic_text.config(state="disabled")
            return
        
        pps = metrics.get("packets_per_second", 0)
        data_mb = metrics.get("data_volume_mb", 0.0)
        flags = metrics.get("suspicious_patterns", {})
        
        self.pps_label.config(text=f"Packets/sec: {pps}")
        self.data_label.config(text=f"Data Transferred: {data_mb:.2f} MB")
        
        flag_text = []
        if flags.get("high_packet_rate"):
            flag_text.append("High Packet Rate")
        if flags.get("unusual_ports_detected"):
            flag_text.append("Unusual Ports")
        if flags.get("large_data_transfer"):
            flag_text.append("Large Transfer")
        
        self.suspicious_label.config(
            text=f"Suspicious Flags: {', '.join(flag_text) if flag_text else 'None'}"
        )
        
        # Update packet log
        recent_packets = metrics.get("recent_packets", [])[-20:]
        self.traffic_text.config(state="normal")
        self.traffic_text.delete(1.0, tk.END)
        
        for pkt in recent_packets:
            line = (f"{pkt.get('source_ip', '')} -> {pkt.get('destination_ip', '')} "
                   f"[{pkt.get('protocol', '')}] Port: {pkt.get('port', 'N/A')} "
                   f"Size: {pkt.get('packet_size', 0)} bytes\n")
            self.traffic_text.insert(tk.END, line)
        
        self.traffic_text.config(state="disabled")
    
    # ================== TAB 5: SESSION HISTORY ==================
    
    def _create_history_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="📜 History")
        
        # Toolbar
        toolbar = ttk.Frame(tab, style="Dark.TFrame")
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="Refresh", 
                  command=self._refresh_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Replay Session", 
                  command=self._replay_selected_session).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Export to CSV", 
                  command=self._export_to_csv).pack(side=tk.LEFT, padx=5)
        # Removed Compare 2 Sessions button (not used, simplifies UI)
        
        # History table
        columns = ("session_id", "username", "login_time", "status", 
                  "final_risk", "apps_accessed")
        self.history_tree = ttk.Treeview(tab, columns=columns, show="headings", height=14, selectmode="extended")
        
        self.history_tree.heading("session_id", text="Session ID")
        self.history_tree.heading("username", text="Username")
        self.history_tree.heading("login_time", text="Login Time")
        self.history_tree.heading("status", text="Status")
        self.history_tree.heading("final_risk", text="Final Risk")
        self.history_tree.heading("apps_accessed", text="Apps Accessed")
        
        self.history_tree.column("session_id", width=250)
        self.history_tree.column("username", width=120)
        self.history_tree.column("login_time", width=180)
        self.history_tree.column("status", width=100)
        self.history_tree.column("final_risk", width=100)
        self.history_tree.column("apps_accessed", width=200)
        
        scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scrollbar.set)
        
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)

        self.timeline_frame = ttk.LabelFrame(tab, text="Threat Timeline", style="Dark.TFrame", padding=10)
        self.timeline_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        timeline_scroll = ttk.Scrollbar(self.timeline_frame, orient=tk.VERTICAL)
        self.timeline_text = tk.Text(
            self.timeline_frame,
            bg=self.BG_MEDIUM,
            fg=self.FG_WHITE,
            font=("Courier", 9),
            yscrollcommand=timeline_scroll.set,
            state="disabled",
            height=10,
            wrap="word",
        )
        timeline_scroll.config(command=self.timeline_text.yview)

        self.timeline_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        timeline_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.history_tree.bind("<<TreeviewSelect>>", self._on_history_selection_change)
        return tab

    def _create_incident_reports_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="📝 Incident Reports")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Incident Reports", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        self._incident_report_rows: dict[str, dict[str, Any]] = {}

        btn_row = ttk.Frame(wrapper, style="Dark.TFrame")
        btn_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btn_row, text="Refresh Reports", command=self._refresh_incident_reports).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_row, text="Export Selected Report", command=self._export_selected_incident_report).pack(side=tk.LEFT, padx=6)

        body = ttk.Frame(wrapper, style="Dark.TFrame")
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)

        left = ttk.LabelFrame(body, text="Stored Reports", style="Dark.TFrame", padding=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ttk.LabelFrame(body, text="Report Details", style="Dark.TFrame", padding=8)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.incident_reports_tree = ttk.Treeview(
            left,
            columns=("timestamp", "session_id", "author"),
            show="headings",
            height=14,
        )
        self.incident_reports_tree.heading("timestamp", text="Timestamp")
        self.incident_reports_tree.heading("session_id", text="Session ID")
        self.incident_reports_tree.heading("author", text="Author")
        self.incident_reports_tree.column("timestamp", width=150)
        self.incident_reports_tree.column("session_id", width=160)
        self.incident_reports_tree.column("author", width=110)
        left_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.incident_reports_tree.yview)
        self.incident_reports_tree.configure(yscroll=left_scroll.set)
        self.incident_reports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        left_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        right_scroll = ttk.Scrollbar(right, orient=tk.VERTICAL)
        self.incident_report_detail_text = tk.Text(
            right,
            bg=self.BG_MEDIUM,
            fg=self.FG_WHITE,
            font=("Courier", 10),
            relief="solid",
            bd=1,
            wrap="word",
            yscrollcommand=right_scroll.set,
        )
        right_scroll.config(command=self.incident_report_detail_text.yview)
        self.incident_report_detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.incident_report_detail_text.insert(
            tk.END,
            "No incident report selected yet.\n\nRefresh to load stored reports, then click one on the left.",
        )
        self.incident_report_detail_text.config(state="disabled")

        self.incident_reports_tree.bind("<<TreeviewSelect>>", self._show_selected_incident_report)
        self._refresh_incident_reports()

        return tab

    def _create_personal_security_status_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=self.BG_DARK)
        self.notebook.add(tab, text="👤 My Security Status")
        
        # Main container with padding
        main_container = tk.Frame(tab, bg=self.BG_DARK)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(main_container, text="Personal Security Status", 
                        bg=self.BG_DARK, fg=self.FG_WHITE, font=("Arial", 18, "bold"))
        title.pack(anchor="w", pady=(0, 20))
        
        # ======== TOP ROW: RISK, POSTURE, TIMER ========
        top_row = tk.Frame(main_container, bg=self.BG_DARK)
        top_row.pack(fill=tk.X, pady=(0, 20))
        top_row.columnconfigure(0, weight=1)
        top_row.columnconfigure(1, weight=1)
        top_row.columnconfigure(2, weight=1)
        
        # Risk Level Card
        risk_card = tk.Frame(top_row, bg=self.BG_MEDIUM, relief="solid", bd=1)
        risk_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        tk.Label(risk_card, text="My Risk Level", bg=self.BG_MEDIUM, fg=self.FG_WHITE, 
                font=("Arial", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 5))
        
        self.personal_risk_badge = tk.Label(risk_card, text="--", bg="#7a7a7a", fg="#ffffff",
                                            font=("Arial", 32, "bold"), relief="solid", bd=2, padx=20, pady=10)
        self.personal_risk_badge.pack(anchor="center", padx=12, pady=10)
        
        self.personal_risk_label = tk.Label(risk_card, text="Calculating...", bg=self.BG_MEDIUM, 
                                           fg=self.FG_WHITE, font=("Arial", 9))
        self.personal_risk_label.pack(anchor="center", padx=12, pady=(0, 10))
        
        # Device Posture Card
        posture_card = tk.Frame(top_row, bg=self.BG_MEDIUM, relief="solid", bd=1)
        posture_card.grid(row=0, column=1, sticky="nsew", padx=5)
        
        tk.Label(posture_card, text="Device Posture Score", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 8))
        
        # Progress bar for posture
        posture_frame = tk.Frame(posture_card, bg=self.BG_MEDIUM)
        posture_frame.pack(fill=tk.X, padx=12, pady=5)
        
        self.personal_posture_canvas = tk.Canvas(posture_frame, bg=self.BG_MEDIUM, height=25, 
                                                 highlightthickness=0)
        self.personal_posture_canvas.pack(fill=tk.X)
        
        self.personal_posture_label = tk.Label(posture_card, text="-- / 100", bg=self.BG_MEDIUM,
                                              fg=self.FG_WHITE, font=("Arial", 9))
        self.personal_posture_label.pack(anchor="center", padx=12, pady=(5, 10))
        
        # Session Timer Card
        timer_card = tk.Frame(top_row, bg=self.BG_MEDIUM, relief="solid", bd=1)
        timer_card.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        
        tk.Label(timer_card, text="Session Time Remaining", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 5))
        
        self.session_timer_label = tk.Label(timer_card, text="00:00", bg=self.BG_MEDIUM, 
                                           fg=self.ACCENT_BLUE, font=("Arial", 28, "bold"))
        self.session_timer_label.pack(anchor="center", padx=12, pady=10)
        
        self.session_timer_warning = tk.Label(timer_card, text="Counting down...", 
                                             bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Arial", 9))
        self.session_timer_warning.pack(anchor="center", padx=12, pady=(0, 10))
        
        # ======== MIDDLE ROW: LOGIN DETAILS & CONNECTION STATUS ========
        middle_row = tk.Frame(main_container, bg=self.BG_DARK)
        middle_row.pack(fill=tk.X, pady=(0, 20))
        middle_row.columnconfigure(0, weight=2)
        middle_row.columnconfigure(1, weight=1)
        
        # Login Details Card
        details_card = tk.Frame(middle_row, bg=self.BG_MEDIUM, relief="solid", bd=1)
        details_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        tk.Label(details_card, text="My Login Details", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 10))
        
        details_text = tk.Frame(details_card, bg=self.BG_MEDIUM)
        details_text.pack(fill=tk.X, padx=12, pady=(0, 10))
        
        self.personal_login_time_label = tk.Label(details_text, text="Login Time: --", 
                                                  bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Arial", 9))
        self.personal_login_time_label.pack(anchor="w", pady=2)
        
        self.personal_ip_label = tk.Label(details_text, text="IP Address: --", 
                                         bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Arial", 9))
        self.personal_ip_label.pack(anchor="w", pady=2)
        
        self.personal_location_label = tk.Label(details_text, text="Location: --", 
                                               bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Arial", 9))
        self.personal_location_label.pack(anchor="w", pady=2)
        
        self.personal_os_label = tk.Label(details_text, text="Device OS: --", 
                                         bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Arial", 9))
        self.personal_os_label.pack(anchor="w", pady=2)
        
        # Connection Security Status Card
        conn_card = tk.Frame(middle_row, bg=self.BG_MEDIUM, relief="solid", bd=1)
        conn_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        
        tk.Label(conn_card, text="Connection Status", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 10))
        
        self.personal_vpn_badge = tk.Label(conn_card, text="🔒 VPN: No", 
                                          bg=self.BG_MEDIUM, fg=self.SUCCESS_GREEN, font=("Arial", 9, "bold"))
        self.personal_vpn_badge.pack(anchor="w", padx=12, pady=2)
        
        self.personal_tor_badge = tk.Label(conn_card, text="🛡 Tor: No", 
                                          bg=self.BG_MEDIUM, fg=self.SUCCESS_GREEN, font=("Arial", 9, "bold"))
        self.personal_tor_badge.pack(anchor="w", padx=12, pady=2)
        
        self.personal_proxy_badge = tk.Label(conn_card, text="🌐 Proxy: No", 
                                            bg=self.BG_MEDIUM, fg=self.SUCCESS_GREEN, font=("Arial", 9, "bold"))
        self.personal_proxy_badge.pack(anchor="w", padx=12, pady=(2, 10))
        
        # ======== BOTTOM SECTION: ALERTS, TIPS, ACCESS LEVEL ========
        bottom_section = tk.Frame(main_container, bg=self.BG_DARK)
        bottom_section.pack(fill=tk.BOTH, expand=True, pady=0)
        bottom_section.columnconfigure(0, weight=1)
        bottom_section.columnconfigure(1, weight=1)
        
        # Recent Alerts Card
        alerts_card = tk.Frame(bottom_section, bg=self.BG_MEDIUM, relief="solid", bd=1)
        alerts_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
        
        tk.Label(alerts_card, text="My Recent Alerts (Last 5)", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(8, 6))
        
        alerts_frame = tk.Frame(alerts_card, bg=self.BG_MEDIUM)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        
        scroll_alerts = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL)
        self.personal_alerts_text = tk.Text(alerts_frame, bg="#f9fafb", fg=self.FG_WHITE,
                                           font=("Courier", 8), height=8, state="disabled",
                                           yscrollcommand=scroll_alerts.set, wrap="word")
        scroll_alerts.config(command=self.personal_alerts_text.yview)
        
        self.personal_alerts_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_alerts.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Security Tips Card
        tips_card = tk.Frame(bottom_section, bg=self.BG_MEDIUM, relief="solid", bd=1)
        tips_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
        
        tk.Label(tips_card, text="💡 Zero Trust Security Tip", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(8, 6))
        
        self.personal_tip_text = tk.Text(tips_card, bg="#f0f7ff", fg=self.FG_WHITE,
                                        font=("Arial", 9), height=8, state="disabled",
                                        wrap="word", relief="flat")
        self.personal_tip_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        
        # ======== ACCESS LEVEL SECTION ========
        access_card = tk.Frame(main_container, bg=self.BG_MEDIUM, relief="solid", bd=1)
        access_card.pack(fill=tk.X, pady=(20, 0))
        
        tk.Label(access_card, text="My Access Level", bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                font=("Arial", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 8))
        
        self.personal_access_label = tk.Label(access_card, text="Loading accessible resources...", 
                                             bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Arial", 9),
                                             justify=tk.LEFT, wraplength=700)
        self.personal_access_label.pack(anchor="w", padx=12, pady=(0, 10))
        
        # Initialize security tips
        self.security_tips_index = 0
        self.security_tips = [
            "🔐 Zero Trust Principle: Never trust, always verify. Every access request must be authenticated and authorized, regardless of source or location.",
            "🛡️ Defense in Depth: Implement multiple layers of security controls. Don't rely on a single defense mechanism.",
            "📊 Continuous Monitoring: Monitor all network traffic and user behavior. Detect anomalies in real-time.",
            "🔑 Least Privilege: Grant users only the minimum permissions necessary to perform their job functions.",
            "🚨 Risk-Based Access: Adjust security requirements based on real-time risk assessment. Higher risk = stronger authentication.",
            "🔍 Device Compliance: Ensure devices meet security baselines before granting access. Posture matters.",
            "🌍 Geolocation & VPN Detection: Flag access from unexpected locations or VPN/Tor exit nodes.",
            "🔗 Microsegmentation: Divide the network into smaller, isolated segments. Limit lateral movement.",
            "📝 Audit Everything: Maintain comprehensive logs of all access attempts and activities.",
            "🔄 Zero Trust Architecture: Assume every connection is untrusted. Verify everything with strong cryptography.",
        ]
        
        return tab

    def _create_ip_blacklist_manager_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="🚫 IP Blacklist Manager")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="IP Blacklist Manager", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Toolbar
        toolbar = ttk.Frame(wrapper, style="Dark.TFrame")
        toolbar.pack(fill=tk.X, padx=0, pady=(0, 10))
        
        ttk.Button(toolbar, text="Refresh", command=self._refresh_ip_blacklist).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Add IP", command=self._add_ip_to_blacklist).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Remove IP", command=self._remove_ip_from_blacklist).pack(side=tk.LEFT, padx=5)
        
        # Blacklist table
        columns = ("ip_address", "reason", "date_blocked", "blocked_by")
        self.blacklist_tree = ttk.Treeview(wrapper, columns=columns, show="headings", height=20)
        
        self.blacklist_tree.heading("ip_address", text="IP Address")
        self.blacklist_tree.heading("reason", text="Reason")
        self.blacklist_tree.heading("date_blocked", text="Date Blocked")
        self.blacklist_tree.heading("blocked_by", text="Blocked By")
        
        self.blacklist_tree.column("ip_address", width=120)
        self.blacklist_tree.column("reason", width=240)
        self.blacklist_tree.column("date_blocked", width=120)
        self.blacklist_tree.column("blocked_by", width=100)
        
        scroll = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=self.blacklist_tree.yview)
        self.blacklist_tree.configure(yscroll=scroll.set)
        
        self.blacklist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._refresh_ip_blacklist()
        return tab

    def _create_policy_simulation_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="🧪 Policy Simulation")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Policy Simulation", style="Title.TLabel").pack(anchor="w", pady=(0, 10))

        form = ttk.Frame(wrapper, style="Dark.TFrame")
        form.pack(fill=tk.X, pady=(6, 12))

        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        uname_entry = tk.Entry(form, width=30)
        uname_entry.grid(row=0, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(form, text="Posture Score (0-100):").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        posture_entry = tk.Entry(form, width=10)
        posture_entry.insert(0, "80")
        posture_entry.grid(row=1, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(form, text="IP Address:").grid(row=2, column=0, sticky="w", padx=6, pady=6)
        ip_entry = tk.Entry(form, width=20)
        ip_entry.insert(0, "127.0.0.1")
        ip_entry.grid(row=2, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(form, text="Login Time (HH:MM):").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        time_entry = tk.Entry(form, width=10)
        time_entry.insert(0, datetime.now().strftime("%H:%M"))
        time_entry.grid(row=3, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(form, text="Traffic Behavior Score (0-100):").grid(row=4, column=0, sticky="w", padx=6, pady=6)
        traffic_entry = tk.Entry(form, width=10)
        traffic_entry.insert(0, "0")
        traffic_entry.grid(row=4, column=1, sticky="w", padx=6, pady=6)

        result_frame = ttk.LabelFrame(wrapper, text="Simulation Result", style="Dark.TFrame", padding=8)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        result_text = tk.Text(result_frame, bg=self.BG_MEDIUM, fg=self.FG_WHITE, height=12, wrap="word")
        result_text.pack(fill=tk.BOTH, expand=True)
        result_text.insert(tk.END, "Fill the fields and click Simulate to compute a risk decision.")
        result_text.config(state="disabled")

        def do_simulate() -> None:
            uname = uname_entry.get().strip() or "student"
            try:
                posture = float(posture_entry.get().strip() or 80.0)
            except Exception:
                posture = 80.0
            ip = ip_entry.get().strip() or "127.0.0.1"
            login_time = time_entry.get().strip() or datetime.now().strftime("%H:%M")
            try:
                traffic = float(traffic_entry.get().strip() or 0.0)
            except Exception:
                traffic = 0.0

            # Use risk_scorer to compute
            res = self.risk_scorer.calculate_risk(
                posture_score=posture,
                login_location="known",
                login_time=login_time,
                ip_reputation=20.0,
                traffic_behavior_score=traffic,
            )

            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Risk Score: {res.get('risk_score')}\n")
            result_text.insert(tk.END, f"Risk Level: {res.get('risk_level')}\n")
            result_text.insert(tk.END, "\nComponent breakdown:\n")
            for k, v in (res.get('component_risk') or {}).items():
                result_text.insert(tk.END, f"- {k}: {v}\n")
            result_text.config(state="disabled")

        ttk.Button(form, text="Simulate", command=do_simulate).grid(row=5, column=0, columnspan=2, pady=10)

        return tab

    def _create_protected_resources_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="🔐 Protected Resources")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Protected Company Applications", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
        tk.Label(
            wrapper,
            text="Select an application to open. Locked resources are denied by RBAC policy.",
            bg=self.BG_DARK,
            fg=self.FG_WHITE,
            font=("Arial", 10),
        ).pack(anchor="w", pady=(0, 12))

        grid = tk.Frame(wrapper, bg=self.BG_DARK)
        grid.pack(fill=tk.BOTH, expand=True)

        for col in range(2):
            grid.columnconfigure(col, weight=1)

        self.resource_buttons: dict[str, tk.Button] = {}

        for idx, (app_id, app_label, app_icon) in enumerate(self.PROTECTED_APPS):
            row = idx // 2
            col = idx % 2

            btn = tk.Button(
                grid,
                text=f"{app_icon}  {app_label}",
                bg="#2f855a",
                fg="#ffffff",
                font=("Arial", 11, "bold"),
                relief="flat",
                padx=12,
                pady=12,
                anchor="w",
                cursor="hand2",
                activebackground="#276749",
                command=lambda a=app_id, n=app_label: self._handle_resource_access(a, n),
            )
            btn.grid(row=row, column=col, sticky="ew", padx=8, pady=8)
            self.resource_buttons[app_id] = btn

        return tab

    def _create_risk_threshold_editor_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="⚙️  Risk Threshold Editor")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Risk Threshold Configuration", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Get current thresholds
        thresholds = self.risk_scorer.get_thresholds()
        low_val = thresholds.get("low_cutoff", 35.0)
        high_val = thresholds.get("high_cutoff", 70.0)
        
        # LOW threshold slider
        low_frame = ttk.Frame(wrapper, style="Dark.TFrame")
        low_frame.pack(fill=tk.X, pady=15)
        
        ttk.Label(low_frame, text="LOW Threshold:", style="TLabel").pack(side=tk.LEFT, padx=5)
        # Create badge BEFORE slider to avoid callback before widget exists
        self.low_badge = tk.Label(low_frame, text=f"{int(low_val)}", bg=self.SUCCESS_GREEN, 
                                  fg="#ffffff", font=("Arial", 9, "bold"), width=5, relief="solid", bd=1)
        self.low_badge.pack(side=tk.LEFT, padx=5)
        self.low_slider = ttk.Scale(low_frame, from_=0, to=50, orient=tk.HORIZONTAL, 
                                    command=lambda v: self._update_low_threshold(float(v)))
        self.low_slider.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.low_slider.set(low_val)
        
        # HIGH threshold slider
        high_frame = ttk.Frame(wrapper, style="Dark.TFrame")
        high_frame.pack(fill=tk.X, pady=15)
        
        ttk.Label(high_frame, text="HIGH Threshold:", style="TLabel").pack(side=tk.LEFT, padx=5)
        # Create badge BEFORE slider to avoid callback before widget exists
        self.high_badge = tk.Label(high_frame, text=f"{int(high_val)}", bg=self.DANGER_RED,
                                   fg="#ffffff", font=("Arial", 9, "bold"), width=5, relief="solid", bd=1)
        self.high_badge.pack(side=tk.LEFT, padx=5)
        self.high_slider = ttk.Scale(high_frame, from_=50, to=100, orient=tk.HORIZONTAL,
                                     command=lambda v: self._update_high_threshold(float(v)))
        self.high_slider.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.high_slider.set(high_val)
        self.high_badge.pack(side=tk.LEFT, padx=5)
        
        # Reset button
        ttk.Button(wrapper, text="Reset to Defaults", command=self._reset_risk_thresholds).pack(pady=20)
        
        return tab

    def _create_device_registry_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="📱 Approved Device Registry")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Approved Device MAC Addresses", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Toolbar
        toolbar = ttk.Frame(wrapper, style="Dark.TFrame")
        toolbar.pack(fill=tk.X, padx=0, pady=(0, 10))
        
        ttk.Button(toolbar, text="Refresh", command=self._refresh_device_registry).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Add MAC", command=self._add_mac_to_registry).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Remove MAC", command=self._remove_mac_from_registry).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Reset", command=self._reset_device_registry).pack(side=tk.LEFT, padx=5)
        
        # Registry table
        columns = ("mac_address", "device_name", "date_added")
        self.device_tree = ttk.Treeview(wrapper, columns=columns, show="headings", height=20)
        
        self.device_tree.heading("mac_address", text="MAC Address")
        self.device_tree.heading("device_name", text="Device Name")
        self.device_tree.heading("date_added", text="Date Added")
        
        self.device_tree.column("mac_address", width=150)
        self.device_tree.column("device_name", width=240)
        self.device_tree.column("date_added", width=120)
        
        scroll = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscroll=scroll.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self._refresh_device_registry()
        return tab

    def _create_audit_log_export_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="📤 Export Audit Logs")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Audit Log Export", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Export options
        options_frame = ttk.LabelFrame(wrapper, text="Export Options", style="Dark.TFrame", padding=12)
        options_frame.pack(fill=tk.X, pady=(0, 16))
        
        ttk.Label(options_frame, text="Select audit date range:").pack(anchor="w", pady=5)
        ttk.Label(options_frame, text="[Currently exports all sessions]", style="TLabel").pack(anchor="w", padx=20)
        
        # Export button
        ttk.Button(options_frame, text="Export to Desktop", command=self._export_audit_logs).pack(pady=10)
        
        # Result display
        result_frame = ttk.LabelFrame(wrapper, text="Export Result", style="Dark.TFrame", padding=12)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        self.export_result_text = tk.Text(result_frame, bg=self.BG_MEDIUM, fg=self.FG_WHITE, 
                                          font=("Courier", 10), height=15, state="disabled")
        self.export_result_text.pack(fill=tk.BOTH, expand=True)
        
        return tab

    def _create_system_health_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="💚 System Health Dashboard")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="System Health & Statistics", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Stats grid
        stats_frame = ttk.Frame(wrapper, style="Dark.TFrame")
        stats_frame.pack(fill=tk.X, padx=0, pady=10)
        
        for col in range(3):
            stats_frame.columnconfigure(col, weight=1)
        
        self.health_stats = {}
        stats_labels = [
            ("total_sessions", "Total Sessions Today", 0, 0),
            ("total_alerts", "Total Alerts", 0, 1),
            ("avg_risk_score", "Avg Risk Score", 0, 2),
            ("blocked_ips", "Blocked IPs", 1, 0),
            ("active_sessions", "Active Sessions", 1, 1),
            ("posture_pass_rate", "Posture Pass Rate", 1, 2),
        ]
        
        for key, label, row, col in stats_labels:
            stat_box = tk.Frame(stats_frame, bg=self.BG_MEDIUM, relief="solid", bd=1)
            stat_box.grid(row=row, column=col, sticky="ew", padx=5, pady=5)
            
            tk.Label(stat_box, text=label, bg=self.BG_MEDIUM, fg=self.FG_WHITE, 
                    font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
            
            value_label = tk.Label(stat_box, text="--", bg=self.BG_MEDIUM, fg=self.ACCENT_BLUE,
                                  font=("Arial", 16, "bold"))
            value_label.pack(anchor="w", padx=10, pady=(2, 8))
            self.health_stats[key] = value_label
        
        # Auto-refresh every 30s
        ttk.Button(wrapper, text="Refresh Now", command=self._update_system_health).pack(pady=10)
        
        self._update_system_health()
        self._schedule_health_refresh()
        
        return tab

    def _create_activity_heatmap_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(tab, text="🔥 User Activity Heatmap")

        wrapper = ttk.Frame(tab, style="Dark.TFrame")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        ttk.Label(wrapper, text="Login Activity Heatmap", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        
        # Heatmap canvas
        heatmap_frame = ttk.Frame(wrapper, style="Dark.TFrame")
        heatmap_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=10)
        
        # Create a real heatmap canvas (24h x 7 days)
        self.heatmap_canvas = tk.Canvas(heatmap_frame, bg=self.BG_MEDIUM, highlightthickness=0, height=500)
        self.heatmap_canvas.pack(fill=tk.BOTH, expand=True)
        self.heatmap_canvas.bind("<Configure>", lambda _e: self._draw_activity_heatmap())
        self._draw_activity_heatmap()
        
        return tab

    def _set_resource_button_state(self, app_id: str, app_label: str, app_icon: str, allowed: bool) -> None:
        btn = self.resource_buttons.get(app_id)
        if not btn:
            return

        btn.unbind("<Enter>")
        btn.unbind("<Leave>")

        if allowed:
            btn.config(
                text=f"{app_icon}  {app_label}",
                bg="#2f855a",
                fg="#ffffff",
                activebackground="#276749",
                cursor="hand2",
            )
        else:
            btn.config(
                text=f"🔒  {app_label}",
                bg="#8a8a8a",
                fg="#f1f1f1",
                activebackground="#8a8a8a",
                cursor="hand2",
            )
            btn.bind("<Enter>", lambda event: self._show_access_denied_tooltip(event))
            btn.bind("<Leave>", lambda event: self._hide_tooltip())

    def _refresh_protected_resources_access(self) -> None:
        if not hasattr(self, "resource_buttons"):
            return

        for app_id, app_label, app_icon in self.PROTECTED_APPS:
            allowed = self.rbac_manager.can_access(self.current_role, app_id)
            self._set_resource_button_state(app_id, app_label, app_icon, allowed)

    def _show_access_denied_tooltip(self, event: tk.Event) -> None:
        self._hide_tooltip()

        tooltip = tk.Toplevel(self.root)
        tooltip.wm_overrideredirect(True)
        tooltip.configure(bg="#1f1f1f")
        tooltip.geometry(f"+{event.x_root + 12}+{event.y_root + 10}")

        tk.Label(
            tooltip,
            text="Access Denied",
            bg="#1f1f1f",
            fg="#ffffff",
            font=("Arial", 9, "bold"),
            padx=8,
            pady=5,
        ).pack()

        self.current_tooltip_window = tooltip

    def _hide_tooltip(self) -> None:
        if self.current_tooltip_window and self.current_tooltip_window.winfo_exists():
            self.current_tooltip_window.destroy()
        self.current_tooltip_window = None

    def _log_resource_access_attempt(self, app_id: str, app_name: str, granted: bool) -> None:
        if not self.current_session_id:
            return

        event_type = "resource_access_granted" if granted else "resource_access_denied"
        self._log_security_event(
            event_type,
            {
                "application_id": app_id,
                "application_name": app_name,
                "granted": granted,
                "role": self.current_role,
                "ip": self.current_ip,
            },
        )

        if granted:
            self.session_manager.log_app_access(self.current_session_id, app_name)

    def _handle_resource_access(self, app_id: str, app_name: str) -> None:
        has_access = self.rbac_manager.can_access(self.current_role, app_id)
        self._log_resource_access_attempt(app_id, app_name, has_access)

        if has_access:
            self._open_mock_application_window(app_id, app_name)
            return

        messagebox.showerror(
            "Access Denied",
            "Your role does not have permission to access this resource. This attempt has been logged.",
        )

    def _open_mock_application_window(self, app_id: str, app_name: str) -> None:
        self.session_manager.reload_from_disk()
        live_sessions = [
            session
            for session_id, session in self.session_manager.sessions.items()
            if not str(session_id).startswith("__") and isinstance(session, dict)
        ]
        live_active_sessions = [session for session in live_sessions if str(session.get("status", "")).lower() == "active"]
        blocked_sessions = [session for session in live_sessions if str(session.get("status", "")).lower() == "blocked"]
        recent_alerts = [alert for alert in reversed(ALERTS[-20:]) if isinstance(alert, dict)]
        traffic_metrics = self.traffic_monitor.get_metrics()
        recent_packets = traffic_metrics.get("recent_packets", [])[-10:]
        blocked_ips = sorted({str(session.get("ip", "")) for session in blocked_sessions if session.get("ip")})

        def fmt_session(session: dict[str, Any]) -> str:
            return (
                f"{session.get('session_id', '')} | {session.get('username', '')} | "
                f"{session.get('role', '')} | {session.get('status', '')} | risk {float(session.get('risk_score', 0.0)):.1f}"
            )

        if app_id == "alerts_dashboard":
            lines = [
                f"Total alerts: {len(ALERTS)}",
                f"Unacknowledged: {sum(1 for alert in ALERTS if not alert.get('acknowledged', False))}",
                "",
            ]
            lines.extend(
                f"{str(alert.get('severity', 'INFO')).upper()}: {str(alert.get('message', ''))[:120]}"
                for alert in recent_alerts[:8]
            )
            if len(lines) == 3:
                lines.append("No alerts available yet.")
        elif app_id == "traffic_log_viewer":
            lines = [
                f"Monitoring active: {'yes' if traffic_metrics.get('capture_running') else 'no'}",
                f"Packets/sec: {traffic_metrics.get('packets_per_second', 0)}",
                f"Data transferred: {traffic_metrics.get('data_volume_mb', 0.0)} MB",
                "",
            ]
            if recent_packets:
                for pkt in recent_packets:
                    ts = datetime.fromtimestamp(float(pkt.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S')
                    lines.append(
                        f"{ts} | {pkt.get('source_ip', '')} -> {pkt.get('destination_ip', '')} | "
                        f"{pkt.get('protocol', '')}/{pkt.get('port', '')} | {pkt.get('packet_size', 0)} bytes"
                    )
            else:
                lines.append("No captured traffic yet. Use Start Monitoring from the Traffic Monitor tab.")
        elif app_id == "threat_report_generator":
            top_session = max(live_sessions, key=lambda s: float(s.get("risk_score", 0.0)), default=None)
            lines = [
                f"Live sessions tracked: {len(live_sessions)}",
                f"Active sessions: {len(live_active_sessions)}",
                f"Blocked sessions: {len(blocked_sessions)}",
                "",
            ]
            if top_session:
                lines.extend([
                    f"Highest risk session: {top_session.get('session_id', '')}",
                    f"User: {top_session.get('username', '')}",
                    f"Role: {top_session.get('role', '')}",
                    f"Risk score: {float(top_session.get('risk_score', 0.0)):.1f}",
                    f"Accessed apps: {', '.join(top_session.get('accessed_apps', [])) or 'None'}",
                ])
            else:
                lines.append("No sessions are available yet.")
        elif app_id == "session_management_console":
            lines = [
                f"Active sessions: {len(live_active_sessions)}",
                f"Blocked sessions: {len(blocked_sessions)}",
                "",
            ]
            lines.extend(fmt_session(session) for session in live_active_sessions[:8])
            if len(lines) == 3:
                lines.append("No active sessions currently recorded.")
        elif app_id == "ip_blacklist_manager":
            lines = [
                f"Blocked IPs: {len(blocked_ips)}",
                "",
            ]
            lines.extend(blocked_ips[:12] if blocked_ips else ["No blocked IPs recorded."])
        elif app_id == "policy_control_panel":
            lines = [
                f"Current role: {self.current_role or 'unknown'}",
                "Accessible protected resources:",
            ]
            accessible = [
                f"- {label}"
                for app_key, label, _icon in self.PROTECTED_APPS
                if self.rbac_manager.can_access(self.current_role, app_key)
            ]
            lines.extend(accessible or ["- No protected resources available for this role."])
        elif app_id == "audit_log_exporter":
            lines = [
                f"Sessions in log: {len(live_sessions)}",
                f"Total alerts: {len(ALERTS)}",
                f"Portal DB audit rows: {len(self.session_manager.sessions.get('__portal_db_audit', [])) if isinstance(self.session_manager.sessions.get('__portal_db_audit'), list) else 0}",
                "",
                "Export is available from the Audit Logs tab.",
            ]
        else:
            lines = ["No live data available."]

        popup = tk.Toplevel(self.root)
        popup.title(app_name)
        popup.geometry("760x420")
        popup.configure(bg="#ffffff")

        tk.Label(
            popup,
            text=app_name,
            bg="#ffffff",
            fg="#1f2937",
            font=("Arial", 15, "bold"),
        ).pack(anchor="w", padx=16, pady=(14, 8))

        tk.Label(
            popup,
            text=f"Opened by {self.current_username} ({self.current_role}) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            bg="#ffffff",
            fg="#4b5563",
            font=("Arial", 9),
        ).pack(anchor="w", padx=16, pady=(0, 10))

        text = tk.Text(
            popup,
            bg="#f7fafc",
            fg="#111827",
            relief="solid",
            bd=1,
            font=("Courier", 10),
            wrap="word",
        )
        text.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

        text.insert(tk.END, "\n".join(lines))
        text.config(state="disabled")

    def _is_advanced_security_role(self) -> bool:
        # Allow SOC operators as well to generate reports
        return self.current_role in {"soc_operator", "threat_analyst", "security_engineer"}

    def _get_selected_session_id(self, tree: ttk.Treeview) -> str | None:
        selection = tree.selection()
        if not selection:
            return None
        values = tree.item(selection[0], "values")
        return str(values[0]) if values else None

    def _extract_session_alerts(self, events: list[dict[str, Any]]) -> list[str]:
        alerts: list[str] = []
        for event in events:
            if event.get("event_type") == "alert":
                details = event.get("details", {})
                severity = str(details.get("severity", "medium")).upper()
                message = str(details.get("message", ""))
                alerts.append(f"{severity}: {message}")
        return alerts

    def _extract_session_anomalies(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        for event in events:
            if event.get("event_type") == "traffic_anomaly_scan":
                details = event.get("details", {})
                anomalies.append(
                    {
                        "timestamp": event.get("timestamp", "unknown"),
                        "is_anomalous": bool(details.get("is_anomalous", False)),
                        "decision": str(details.get("decision", "allow")),
                        "reason": str(details.get("reason", "")),
                        "traffic_flags": details.get("traffic_flags", {}),
                    }
                )
        return anomalies

    def _calculate_session_duration(self, session: dict[str, Any], events: list[dict[str, Any]]) -> str:
        login_time_iso = str(session.get("login_time", ""))
        if not login_time_iso:
            return "N/A"

        try:
            start_time = datetime.fromisoformat(login_time_iso)
        except ValueError:
            return "N/A"

        end_time = datetime.now(start_time.tzinfo)
        for event in events:
            if event.get("event_type") == "logout":
                ts = str(event.get("timestamp", ""))
                try:
                    end_time = datetime.fromisoformat(ts)
                except ValueError:
                    pass
                break

        duration = end_time - start_time
        total_seconds = max(0, int(duration.total_seconds()))
        hours, rem = divmod(total_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _build_incident_report_text(self, session_id: str) -> str:
        self.session_manager.reload_from_disk()
        session = self.session_manager.sessions.get(session_id)
        if not session:
            return "Session record not found."

        events = list(session.get("events", []))
        alerts = self._extract_session_alerts(events)
        anomalies = self._extract_session_anomalies(events)

        last_anomaly = anomalies[-1] if anomalies else {}
        anomaly_decision = str(last_anomaly.get("decision", "allow")).upper() if anomalies else "ALLOW"
        posture_score = session.get("device_posture_score", "N/A")
        duration = self._calculate_session_duration(session, events)

        anomaly_lines = [
            (
                f"- {entry['timestamp']} | anomalous={entry['is_anomalous']} | "
                f"decision={entry['decision']} | reason={entry['reason']}"
            )
            for entry in anomalies
        ]

        timestamps = [str(session.get("login_time", ""))]
        timestamps.extend(str(event.get("timestamp", "")) for event in events)
        timestamps = [ts for ts in timestamps if ts]

        report_lines = [
            "=" * 82,
            "ZTNA Sentinel - Incident Report",
            "=" * 82,
            f"Report Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Session ID: {session_id}",
            "",
            "Session Profile",
            "-" * 82,
            f"Username: {session.get('username', 'N/A')}",
            f"Role: {session.get('role', 'N/A')}",
            f"Login Time: {session.get('login_time', 'N/A')}",
            f"Risk Score: {float(session.get('risk_score', 0.0)):.1f}",
            f"Device Posture Score: {posture_score}",
            f"Session Duration: {duration}",
            "",
            "Alerts Triggered",
            "-" * 82,
            *(alerts if alerts else ["- No alerts were triggered."]),
            "",
            "Traffic Anomalies Detected",
            "-" * 82,
            *(anomaly_lines if anomaly_lines else ["- No traffic anomalies recorded."]),
            "",
            "Anomaly Detector Decision",
            "-" * 82,
            f"Final Decision: {anomaly_decision}",
            f"Recommended Action: {str(last_anomaly.get('decision', 'allow')).upper()}",
            f"Reason: {str(last_anomaly.get('reason', 'No anomaly rationale recorded.'))}",
            "",
            "All Timestamps",
            "-" * 82,
            *[f"- {ts}" for ts in timestamps],
            "",
            "End Of Report",
            "=" * 82,
        ]
        return "\n".join(report_lines)

    def _save_report_to_desktop(self, report_text: str, session_id: str) -> None:
        desktop_path = Path.home() / "Desktop"
        safe_session_id = session_id.replace(":", "_").replace("/", "_")
        filename = f"incident_report_{safe_session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_path = desktop_path / filename

        try:
            output_path.write_text(report_text, encoding="utf-8")
            messagebox.showinfo("Saved", f"Incident report saved to:\n{output_path}")
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Could not save report:\n{exc}")

    def _generate_incident_report(self) -> None:
        if not self._is_advanced_security_role():
            return

        session_id = self._get_selected_session_id(self.sessions_tree)
        if not session_id:
            messagebox.showwarning("Warning", "Please select a session to generate report.")
            return

        report_text = self._build_incident_report_text(session_id)

        # Persist generated incident report for SOC review
        try:
            self.session_manager.add_incident_report(session_id, report_text, self.current_username or "system")
        except Exception:
            pass
        try:
            # Refresh Incident Reports tab so SOC can immediately see the newly generated report
            self._refresh_incident_reports()
        except Exception:
            pass

        popup = tk.Toplevel(self.root)
        popup.title(f"Incident Report - {session_id}")
        popup.geometry("900x620")
        popup.configure(bg=self.BG_DARK)

        ttk.Label(popup, text="Incident Report Generator", style="Title.TLabel").pack(anchor="w", padx=12, pady=(10, 6))

        text_frame = ttk.Frame(popup, style="Dark.TFrame")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
        report_widget = tk.Text(
            text_frame,
            bg=self.BG_MEDIUM,
            fg=self.FG_WHITE,
            font=("Courier", 9),
            yscrollcommand=scroll.set,
            wrap="word",
        )
        scroll.config(command=report_widget.yview)
        report_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        report_widget.insert(tk.END, report_text)
        report_widget.config(state="disabled")

        controls = ttk.Frame(popup, style="Dark.TFrame")
        controls.pack(fill=tk.X, padx=12, pady=(0, 10))

        ttk.Button(
            controls,
            text="Save to Desktop",
            command=lambda: self._save_report_to_desktop(report_text, session_id),
        ).pack(side=tk.LEFT)

        ttk.Button(controls, text="Close", command=popup.destroy).pack(side=tk.RIGHT)

    def _run_manual_anomaly_scan(self) -> None:
        if not self._is_advanced_security_role():
            return

        if not self.current_session_id:
            messagebox.showwarning("Warning", "No active session found for manual anomaly scan.")
            return

        metrics = self.traffic_monitor.get_metrics()
        traffic_score = float(metrics.get("traffic_behavior_score", 0.0))
        flags = metrics.get("suspicious_patterns", {})

        summary = {
            "user": self.current_username,
            "ip": self.current_ip,
            "role": self.current_role,
            "risk_score": traffic_score,
            "traffic_flags": flags,
            "accessed_apps": self.session_manager.sessions.get(self.current_session_id, {}).get("accessed_apps", []),
            "login_time": datetime.now().strftime("%H:%M:%S"),
            "login_location": "known",
        }

        result = self.anomaly_detector.analyze_session(summary)

        risk_factors: list[str] = []
        if traffic_score >= 50:
            risk_factors.append(f"Elevated traffic behavior score: {traffic_score:.1f}")
        if isinstance(flags, dict):
            if flags.get("high_packet_rate"):
                risk_factors.append("High packet rate detected")
            if flags.get("unusual_ports_detected"):
                risk_factors.append("Unusual destination ports detected")
            if flags.get("large_data_transfer"):
                risk_factors.append("Large data transfer in progress")

        if not risk_factors:
            risk_factors.append("No significant risk factors detected")

        self._log_security_event(
            "manual_anomaly_scan",
            {
                "decision": result.get("recommended_action", "allow"),
                "is_anomalous": bool(result.get("is_anomalous", False)),
                "reason": result.get("reason", ""),
                "risk_factors": risk_factors,
                "traffic_flags": flags,
            },
        )

        self._show_manual_anomaly_popup(result, risk_factors)

    def _show_manual_anomaly_popup(self, result: dict[str, Any], risk_factors: list[str]) -> None:
        popup = tk.Toplevel(self.root)
        popup.title("Manual Anomaly Scan Result")
        popup.geometry("760x460")
        popup.configure(bg="#ffffff")

        decision = str(result.get("recommended_action", "allow")).lower()
        if decision == "block":
            decision_color = self.DANGER_RED
        elif decision == "challenge":
            decision_color = self.WARNING_YELLOW
        else:
            decision_color = self.SUCCESS_GREEN

        tk.Label(
            popup,
            text="Manual Anomaly Scan",
            bg="#ffffff",
            fg="#111827",
            font=("Arial", 15, "bold"),
        ).pack(anchor="w", padx=16, pady=(12, 6))

        content = tk.Text(
            popup,
            bg="#f8fafc",
            fg="#111827",
            font=("Courier", 10),
            relief="solid",
            bd=1,
            wrap="word",
        )
        content.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

        content.insert(tk.END, f"Decision: {decision.upper()}\n")
        content.tag_add("decision", "1.0", "1.end")
        content.tag_configure("decision", foreground=decision_color, font=("Courier", 10, "bold"))
        content.insert(tk.END, f"Reason: {result.get('reason', 'N/A')}\n\n")
        content.insert(tk.END, "Risk Factors Found:\n")
        for factor in risk_factors:
            content.insert(tk.END, f"- {factor}\n")
        content.insert(
            tk.END,
            f"\nRecommended Action: {str(result.get('recommended_action', 'allow')).upper()}\n",
        )
        content.config(state="disabled")

    def _severity_for_event(self, event: dict[str, Any]) -> str:
        event_type = str(event.get("event_type", "")).lower()
        details = event.get("details", {}) if isinstance(event.get("details", {}), dict) else {}

        if event_type in {"security_incident", "resource_access_denied"}:
            return "critical"
        if event_type == "alert":
            severity = str(details.get("severity", "medium")).lower()
            if severity in {"high", "critical"}:
                return "critical"
            return "warning"
        if event_type in {"traffic_anomaly_scan", "manual_anomaly_scan"} and details.get("is_anomalous"):
            return "warning"
        return "normal"

    def _on_history_selection_change(self, _event: tk.Event) -> None:
        if not self._is_advanced_security_role():
            return

        selection = self.history_tree.selection()
        if len(selection) != 1:
            self.timeline_text.config(state="normal")
            self.timeline_text.delete(1.0, tk.END)
            self.timeline_text.insert(1.0, "Select one session to view timeline, or two sessions for comparison.")
            self.timeline_text.config(state="disabled")
            return

        values = self.history_tree.item(selection[0], "values")
        session_id = str(values[0]) if values else ""
        self._render_timeline_for_session(session_id)

    def _render_timeline_for_session(self, session_id: str) -> None:
        self.session_manager.reload_from_disk()
        session = self.session_manager.sessions.get(session_id, {})
        events = list(session.get("events", []))

        self.timeline_text.config(state="normal")
        self.timeline_text.delete(1.0, tk.END)

        if not events:
            self.timeline_text.insert(1.0, "No timeline events available for this session.")
            self.timeline_text.config(state="disabled")
            return

        self.timeline_text.tag_configure("dot_green", foreground="#2f855a")
        self.timeline_text.tag_configure("dot_yellow", foreground="#d69e2e")
        self.timeline_text.tag_configure("dot_red", foreground="#c53030")
        self.timeline_text.tag_configure("entry_text", foreground=self.FG_WHITE)

        self.timeline_text.insert(tk.END, f"Timeline for Session {session_id}\n\n", "entry_text")

        for event in events:
            timestamp = str(event.get("timestamp", "unknown"))
            event_type = str(event.get("event_type", "unknown"))
            severity = self._severity_for_event(event)

            dot_tag = "dot_green"
            if severity == "warning":
                dot_tag = "dot_yellow"
            elif severity == "critical":
                dot_tag = "dot_red"

            self.timeline_text.insert(tk.END, "● ", dot_tag)
            self.timeline_text.insert(tk.END, f"{timestamp}  |  {event_type}\n", "entry_text")

        self.timeline_text.config(state="disabled")

    def _compare_selected_sessions(self) -> None:
        if not self._is_advanced_security_role():
            return

        selection = self.history_tree.selection()
        if len(selection) != 2:
            messagebox.showwarning("Warning", "Select exactly two sessions for comparison.")
            return

        session_ids: list[str] = []
        for item in selection:
            values = self.history_tree.item(item, "values")
            if values:
                session_ids.append(str(values[0]))

        if len(session_ids) != 2:
            messagebox.showerror("Error", "Could not resolve selected sessions.")
            return

        self.session_manager.reload_from_disk()
        left = self.session_manager.sessions.get(session_ids[0], {})
        right = self.session_manager.sessions.get(session_ids[1], {})

        def build_summary(session: dict[str, Any]) -> str:
            events = list(session.get("events", []))
            alerts = self._extract_session_alerts(events)
            anomalies = self._extract_session_anomalies(events)
            anomaly_count = sum(1 for a in anomalies if a.get("is_anomalous"))
            posture = session.get("device_posture_score", "N/A")
            return "\n".join(
                [
                    f"Session ID: {session.get('session_id', 'N/A')}",
                    f"Username: {session.get('username', 'N/A')}",
                    f"Role: {session.get('role', 'N/A')}",
                    f"Risk Score: {float(session.get('risk_score', 0.0)):.1f}",
                    f"Device Posture: {posture}",
                    f"Alerts Triggered: {len(alerts)}",
                    f"Anomalies Detected: {anomaly_count}",
                    "Alert Details:",
                    *(alerts if alerts else ["- None"]),
                ]
            )

        popup = tk.Toplevel(self.root)
        popup.title("Session Comparison Tool")
        popup.geometry("980x560")
        popup.configure(bg=self.BG_DARK)

        ttk.Label(popup, text="Session Comparison Tool", style="Title.TLabel").pack(anchor="w", padx=12, pady=(10, 8))

        body = ttk.Frame(popup, style="Dark.TFrame")
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        left_text = tk.Text(body, bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Courier", 9), relief="solid", bd=1)
        right_text = tk.Text(body, bg=self.BG_MEDIUM, fg=self.FG_WHITE, font=("Courier", 9), relief="solid", bd=1)
        left_text.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right_text.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        left_text.insert(tk.END, build_summary(left))
        right_text.insert(tk.END, build_summary(right))
        left_text.config(state="disabled")
        right_text.config(state="disabled")
    
    def _refresh_history(self) -> None:
        self.session_manager.reload_from_disk()
        
        # Clear existing
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Add all sessions
        for sid, session in self.session_manager.sessions.items():
            # Skip non-dict entries and metadata keys
            if not isinstance(session, dict) or sid.startswith("__"):
                continue
            values = (
                sid,
                session.get("username", ""),
                session.get("login_time", ""),
                session.get("status", ""),
                f"{session.get('risk_score', 0):.1f}",
                ", ".join(session.get("accessed_apps", [])) or "None",
            )
            self.history_tree.insert("", tk.END, values=values)
    
    def _replay_selected_session(self) -> None:
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a session to replay.")
            return
        
        item = selection[0]
        values = self.history_tree.item(item, "values")
        session_id = values[0]
        
        events = self.session_manager.replay_session(session_id)
        
        if not events:
            messagebox.showinfo("No Events", "No events recorded for this session.")
            return
        
        # Create replay popup
        popup = tk.Toplevel(self.root)
        popup.title(f"Session Replay: {session_id}")
        popup.geometry("700x500")
        popup.configure(bg=self.BG_DARK)
        
        ttk.Label(popup, text=f"Replaying Session: {session_id}", 
                 style="Title.TLabel").pack(pady=10)
        
        text_frame = ttk.Frame(popup, style="Dark.TFrame")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
        text_widget = tk.Text(text_frame, bg=self.BG_MEDIUM, fg=self.FG_WHITE,
                             font=("Courier", 9), yscrollcommand=scrollbar.set)
        scrollbar.config(command=text_widget.yview)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Display events
        for event in events:
            timestamp = event.get("timestamp", "")
            event_type = event.get("event_type", "")
            details = json.dumps(event.get("details", {}), indent=2)
            
            text_widget.insert(tk.END, f"[{timestamp}] {event_type.upper()}\n")
            text_widget.insert(tk.END, f"{details}\n")
            text_widget.insert(tk.END, "-" * 70 + "\n\n")
        
        text_widget.config(state="disabled")
        
        ttk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)
    
    def _export_to_csv(self) -> None:
        self.session_manager.reload_from_disk()
        
        csv_path = self.base_dir / "session_history_export.csv"
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Session ID", "Username", "Role", "IP", 
                               "Login Time", "Status", "Risk Score", "Apps Accessed"])
                
                for sid, session in self.session_manager.sessions.items():
                    # Skip non-dict entries and metadata keys
                    if not isinstance(session, dict) or sid.startswith("__"):
                        continue
                    writer.writerow([
                        sid,
                        session.get("username", ""),
                        session.get("role", ""),
                        session.get("ip", ""),
                        session.get("login_time", ""),
                        session.get("status", ""),
                        session.get("risk_score", 0),
                        ";".join(session.get("accessed_apps", [])),
                    ])
            
            messagebox.showinfo("Success", f"Session history exported to:\n{csv_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed:\n{e}")
    
    # ================== ADMIN TAB HELPERS: IP BLACKLIST ==================
    
    def _refresh_ip_blacklist(self) -> None:
        """Refresh the IP blacklist table from sessions_log.json."""
        if not hasattr(self, "blacklist_tree"):
            return
        
        for item in self.blacklist_tree.get_children():
            self.blacklist_tree.delete(item)
        
        # Prefer explicit blocked IP list persisted in sessions_log.json
        self.session_manager.reload_from_disk()
        blocked_list = []
        try:
            blocked_list = self.session_manager.list_blocked_ips()
        except Exception:
            blocked_list = []

        if blocked_list:
            for rec in blocked_list:
                self.blacklist_tree.insert("", "end", values=(
                    rec.get("ip", ""),
                    rec.get("reason", ""),
                    rec.get("date_blocked", datetime.now().strftime("%Y-%m-%d")),
                    rec.get("blocked_by", self.current_username or "system"),
                ))
            return

        # Fallback: infer from blocked sessions
        blocked_ips = set()
        for session_id, session in self.session_manager.sessions.items():
            if not isinstance(session, dict) or session_id.startswith("__"):
                continue
            if session.get("status") == "blocked":
                ip = session.get("ip", "Unknown")
                blocked_ips.add(ip)

        for ip in sorted(blocked_ips):
            self.blacklist_tree.insert("", "end", values=(
                ip,
                "Session blocked - high risk",
                datetime.now().strftime("%Y-%m-%d"),
                self.current_username or "system"
            ))
    
    def _add_ip_to_blacklist(self) -> None:
        """Add an IP address to the blacklist."""
        popup = tk.Toplevel(self.root)
        popup.title("Add IP to Blacklist")
        popup.geometry("400x200")
        popup.configure(bg="#ffffff")
        
        tk.Label(popup, text="Add IP to Blacklist", bg="#ffffff", fg="#111827",
                font=("Arial", 12, "bold")).pack(anchor="w", padx=15, pady=(12, 6))
        
        tk.Label(popup, text="IP Address:", bg="#ffffff", fg="#111827").pack(anchor="w", padx=15)
        ip_entry = tk.Entry(popup, width=30)
        ip_entry.pack(padx=15, pady=5)
        
        tk.Label(popup, text="Reason:", bg="#ffffff", fg="#111827").pack(anchor="w", padx=15)
        reason_entry = tk.Entry(popup, width=30)
        reason_entry.pack(padx=15, pady=5)
        
        def save_ip():
            ip = ip_entry.get().strip()
            reason = reason_entry.get().strip() or "Administrative block"
            if ip:
                try:
                    self.session_manager.add_blocked_ip(ip, reason, self.current_username or "system")
                except Exception:
                    # Fallback to logging as a session event if persistence fails
                    self._log_security_event("ip_blacklist_add", {
                        "ip": ip,
                        "reason": reason,
                        "admin": self.current_username,
                    })
                self._refresh_ip_blacklist()
                popup.destroy()
                messagebox.showinfo("Success", f"IP {ip} added to blacklist.")
        
        ttk.Button(popup, text="Save", command=save_ip).pack(pady=10)
    
    def _remove_ip_from_blacklist(self) -> None:
        """Remove selected IP from blacklist."""
        selection = self.blacklist_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select an IP to remove.")
            return
        
        item = selection[0]
        values = self.blacklist_tree.item(item, "values")
        ip = str(values[0]) if values else None
        
        if ip:
            self._log_security_event("ip_blacklist_remove", {
                "ip": ip,
                "admin": self.current_username,
            })
            self.blacklist_tree.delete(item)
            messagebox.showinfo("Success", f"IP {ip} removed from blacklist.")

    # ================== ADMIN TAB HELPERS: RISK THRESHOLDS ==================
    
    def _update_low_threshold(self, value: float) -> None:
        """Update LOW threshold slider."""
        val = int(float(value))
        if hasattr(self, 'low_badge'):
            self.low_badge.config(text=str(val))
        # Apply to risk scorer
        current_high = self.risk_scorer.HIGH_CUTOFF
        self.risk_scorer.set_thresholds(val, max(val + 1, current_high))
    
    def _update_high_threshold(self, value: float) -> None:
        """Update HIGH threshold slider."""
        val = int(float(value))
        if hasattr(self, 'high_badge'):
            self.high_badge.config(text=str(val))
        # Apply to risk scorer
        current_low = self.risk_scorer.LOW_CUTOFF
        self.risk_scorer.set_thresholds(current_low, val)
    
    def _reset_risk_thresholds(self) -> None:
        """Reset thresholds to defaults."""
        self.risk_scorer.reset_thresholds()
        thresholds = self.risk_scorer.get_thresholds()
        self.low_slider.set(thresholds["low_cutoff"])
        self.high_slider.set(thresholds["high_cutoff"])
        self.low_badge.config(text=str(int(thresholds["low_cutoff"])))
        self.high_badge.config(text=str(int(thresholds["high_cutoff"])))
        messagebox.showinfo("Success", "Risk thresholds reset to defaults.")

    # ================== ADMIN TAB HELPERS: DEVICE REGISTRY ==================
    
    def _refresh_device_registry(self) -> None:
        """Refresh device MAC registry table."""
        if not hasattr(self, "device_tree"):
            return
        
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        macs = DevicePostureChecker.get_approved_macs()
        for mac in sorted(macs):
            self.device_tree.insert("", "end", values=(
                mac,
                f"Device {len(macs)}",
                datetime.now().strftime("%Y-%m-%d")
            ))
    
    def _add_mac_to_registry(self) -> None:
        """Add a MAC address to approved devices."""
        popup = tk.Toplevel(self.root)
        popup.title("Add MAC Address")
        popup.geometry("400x180")
        popup.configure(bg="#ffffff")
        
        tk.Label(popup, text="Add MAC Address", bg="#ffffff", fg="#111827",
                font=("Arial", 12, "bold")).pack(anchor="w", padx=15, pady=(12, 6))
        
        tk.Label(popup, text="MAC Address (XX:XX:XX:XX:XX:XX):", bg="#ffffff", fg="#111827").pack(anchor="w", padx=15)
        mac_entry = tk.Entry(popup, width=30)
        mac_entry.pack(padx=15, pady=5)
        
        def save_mac():
            mac = mac_entry.get().strip().upper()
            if DevicePostureChecker.add_approved_mac(mac):
                self._refresh_device_registry()
                self._log_security_event("device_mac_added", {"mac": mac})
                popup.destroy()
                messagebox.showinfo("Success", f"MAC {mac} added to registry.")
            else:
                messagebox.showerror("Error", "Invalid MAC format. Use XX:XX:XX:XX:XX:XX")
        
        ttk.Button(popup, text="Add", command=save_mac).pack(pady=10)
    
    def _remove_mac_from_registry(self) -> None:
        """Remove selected MAC from approved devices."""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a MAC to remove.")
            return
        
        item = selection[0]
        values = self.device_tree.item(item, "values")
        mac = str(values[0]) if values else None
        
        if mac and DevicePostureChecker.remove_approved_mac(mac):
            self.device_tree.delete(item)
            self._log_security_event("device_mac_removed", {"mac": mac})
            messagebox.showinfo("Success", f"MAC {mac} removed from registry.")
    
    def _reset_device_registry(self) -> None:
        """Reset MAC registry to defaults."""
        if messagebox.askyesno("Confirm", "Reset MAC registry to defaults?"):
            DevicePostureChecker.reset_approved_macs()
            self._refresh_device_registry()
            self._log_security_event("device_mac_reset", {})
            messagebox.showinfo("Success", "Device registry reset.")

    # ================== ADMIN TAB HELPERS: AUDIT LOG EXPORT ==================
    
    def _export_audit_logs(self) -> None:
        """Export sessions_log.json as formatted .txt report to Desktop."""
        from pathlib import Path as PathlibPath
        
        try:
            self.session_manager.reload_from_disk()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ZTNA_Audit_Log_{timestamp}.txt"
            desktop_path = PathlibPath.home() / "Desktop" / filename
            
            with open(desktop_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ZTNA SENTINEL - AUDIT LOG EXPORT\n")
                f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"Exported by: {self.current_username}\n")
                f.write("=" * 80 + "\n\n")
                
                total_sessions = len(self.session_manager.sessions)
                f.write(f"Total Sessions: {total_sessions}\n\n")
                
                for session_id, session in sorted(self.session_manager.sessions.items()):
                    # Skip non-dict entries and metadata keys
                    if not isinstance(session, dict) or session_id.startswith("__"):
                        continue
                    f.write(f"Session ID: {session_id}\n")
                    f.write(f"  Username: {session.get('username', 'N/A')}\n")
                    f.write(f"  Role: {session.get('role', 'N/A')}\n")
                    f.write(f"  IP: {session.get('ip', 'N/A')}\n")
                    f.write(f"  Login Time: {session.get('login_time', 'N/A')}\n")
                    f.write(f"  Status: {session.get('status', 'N/A')}\n")
                    f.write(f"  Risk Score: {session.get('risk_score', 'N/A')}\n")
                    
                    events = session.get("events", [])
                    f.write(f"  Events ({len(events)}):\n")
                    for evt in events:
                        f.write(f"    - {evt.get('timestamp', 'N/A')}: {evt.get('event_type', 'N/A')}\n")
                    f.write("\n")
            
            self._log_security_event("audit_log_export", {"filename": filename})
            
            self.export_result_text.config(state="normal")
            self.export_result_text.delete(1.0, tk.END)
            self.export_result_text.insert(tk.END, f"✓ Export Successful\n\n")
            self.export_result_text.insert(tk.END, f"File: {filename}\n")
            self.export_result_text.insert(tk.END, f"Path: {desktop_path}\n")
            self.export_result_text.insert(tk.END, f"Size: {desktop_path.stat().st_size} bytes\n")
            self.export_result_text.insert(tk.END, f"Sessions: {total_sessions}\n")
            self.export_result_text.config(state="disabled")
            
            messagebox.showinfo("Success", f"Audit logs exported to:\n{desktop_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed:\n{e}")

    # ================== ADMIN TAB HELPERS: SYSTEM HEALTH ==================
    
    def _update_system_health(self) -> None:
        """Update system health statistics."""
        self.session_manager.reload_from_disk()
        
        today = datetime.now().strftime("%Y-%m-%d")
        sessions_today = 0
        total_alerts = 0
        total_risk = 0.0
        session_count = 0
        blocked_ips = set()
        active_sessions = 0
        posture_checks = 0
        posture_pass = 0
        
        for sid, session in self.session_manager.sessions.items():
            # Skip non-dict entries (like __login_attempts, __failed_logins lists) and metadata keys
            if not isinstance(session, dict) or sid.startswith("__"):
                continue
            session_today = session.get("login_time", "").startswith(today)
            if session_today:
                sessions_today += 1
            
            if session.get("status") == "active":
                active_sessions += 1
            
            if session.get("status") == "blocked":
                blocked_ips.add(session.get("ip", ""))
            
            total_risk += float(session.get("risk_score", 0))
            session_count += 1
            
            events = session.get("events", [])
            total_alerts += sum(1 for e in events if e.get("event_type") == "alert")
            posture = session.get("device_posture_score", None)
            if posture is not None:
                posture_checks += 1
                if float(posture) >= 70:
                    posture_pass += 1
        
        avg_risk = total_risk / max(1, session_count)
        posture_rate = (posture_pass / max(1, posture_checks)) * 100 if posture_checks > 0 else 0
        
        self.health_stats["total_sessions"].config(text=str(sessions_today))
        self.health_stats["total_alerts"].config(text=str(total_alerts))
        self.health_stats["avg_risk_score"].config(text=f"{avg_risk:.1f}")
        self.health_stats["blocked_ips"].config(text=str(len(blocked_ips)))
        self.health_stats["active_sessions"].config(text=str(active_sessions))
        self.health_stats["posture_pass_rate"].config(text=f"{posture_rate:.0f}%")
    
    def _schedule_health_refresh(self) -> None:
        """Schedule health refresh every 30 seconds."""
        if hasattr(self, "health_stats"):
            self.root.after(30000, self._schedule_health_refresh)
            self._update_system_health()

    # ================== ADMIN TAB HELPERS: ACTIVITY HEATMAP ==================
    
    def _draw_activity_heatmap(self) -> None:
        """Draw a 24x7 login activity heatmap (hours x weekdays)."""
        self.session_manager.reload_from_disk()

        # Counts[day][hour], day: Mon=0..Sun=6
        counts = [[0 for _ in range(24)] for _ in range(7)]
        total_points = 0
        for sid, session in self.session_manager.sessions.items():
            if not isinstance(session, dict) or sid.startswith("__"):
                continue
            login_time = str(session.get("login_time", "") or "").strip()
            if not login_time:
                continue
            try:
                dt = datetime.fromisoformat(login_time.replace("Z", ""))
            except ValueError:
                continue
            day = dt.weekday()
            hour = dt.hour
            print(f"Login: {dt} day={dt.weekday()} hour={dt.hour}")
            if 0 <= day < 7 and 0 <= hour < 24:
                counts[day][hour] += 1
                total_points += 1

        canvas = self.heatmap_canvas
        canvas.delete("all")

        cell_w = 40
        cell_h = 40
        origin_x = 70
        origin_y = 50
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

        def color_for_count(c: int) -> str:
            if c <= 0:
                return "#e0e0e0"
            if c <= 2:
                return "#bbdefb"
            if c <= 5:
                return "#64b5f6"
            if c <= 10:
                return "#1976d2"
            return "#0d47a1"

        # Hour labels
        for hour in range(24):
            x = origin_x + hour * cell_w + cell_w // 2
            canvas.create_text(x, origin_y - 14, text=f"{hour:02d}", fill="#333333", font=("Arial", 8, "bold"))

        # Day labels + cells
        for day in range(7):
            y = origin_y + day * cell_h + cell_h // 2
            canvas.create_text(origin_x - 30, y, text=days[day], fill="#333333", font=("Arial", 9, "bold"))
            for hour in range(24):
                c = counts[day][hour]
                x1 = origin_x + hour * cell_w
                y1 = origin_y + day * cell_h
                x2 = x1 + cell_w
                y2 = y1 + cell_h
                canvas.create_rectangle(x1, y1, x2, y2, fill=color_for_count(c), outline="#b0b0b0")

        # Legend
        legend_y = origin_y + 7 * cell_h + 28
        legend = [
            ("0", "#e0e0e0"),
            ("1-2", "#bbdefb"),
            ("3-5", "#64b5f6"),
            ("6-10", "#1976d2"),
            ("10+", "#0d47a1"),
        ]
        lx = origin_x
        canvas.create_text(lx - 40, legend_y + 10, text="Legend:", fill="#333333", font=("Arial", 9, "bold"), anchor="w")
        lx += 20
        for label, color in legend:
            canvas.create_rectangle(lx, legend_y, lx + 24, legend_y + 16, fill=color, outline="#888888")
            canvas.create_text(lx + 34, legend_y + 8, text=label, fill="#333333", font=("Arial", 8), anchor="w")
            lx += 80

        if total_points == 0:
            canvas.create_text(
                origin_x + (24 * cell_w) // 2,
                legend_y + 40,
                text="No login data yet",
                fill="#555555",
                font=("Arial", 10, "italic"),
            )

    # ================== PERSONAL SECURITY STATUS DASHBOARD ==================
    
    def _update_personal_security_status(self) -> None:
        """Update all personal security dashboard widgets."""
        if not self.current_session_id:
            return
        
        self.session_manager.reload_from_disk()
        session = self.session_manager.sessions.get(self.current_session_id, {})
        
        # Update risk level
        self._update_personal_risk_display(session)
        
        # Update posture score
        self._update_personal_posture_display(session)
        
        # Update session timer (every 1 second)
        self._update_personal_session_timer()
        
        # Update login details
        self._update_personal_login_details(session)
        
        # Update connection security status
        self._update_personal_connection_status()
        
        # Update recent alerts (every 5 seconds)
        self._update_personal_alerts()
        
        # Rotate security tips (every 30 seconds)
        self._rotate_security_tips()
        
        # Update access level
        self._update_personal_access_level()
        
        # Schedule next update
        # Schedule next update (5s to avoid UI pressure)
        self._personal_status_after_id = self.root.after(5000, self._update_personal_security_status)
    
    def _update_personal_risk_display(self, session: dict) -> None:
        """Update risk level badge with color coding."""
        risk_score = float(session.get("risk_score", 0.0))
        risk_level = self.risk_scorer._risk_level(risk_score)
        
        if risk_level == "LOW":
            color = self.SUCCESS_GREEN
            text_color = "#ffffff"
        elif risk_level == "MEDIUM":
            color = self.WARNING_YELLOW
            text_color = "#000000"
        else:
            color = self.DANGER_RED
            text_color = "#ffffff"
        
        self.personal_risk_badge.config(text=f"{risk_score:.1f}", bg=color, fg=text_color)
        self.personal_risk_label.config(text=f"Risk Level: {risk_level}")
    
    def _update_personal_posture_display(self, session: dict) -> None:
        """Update device posture progress bar."""
        posture_score = float(session.get("device_posture_score", 0.0))
        
        # Draw progress bar
        canvas = self.personal_posture_canvas
        canvas.delete("all")
        
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        
        if width < 10:
            width = 200
        
        bar_height = 20
        bar_y = (height - bar_height) // 2
        
        # Background
        canvas.create_rectangle(0, bar_y, width, bar_y + bar_height,
                               fill="#e0e0e0", outline="#999999")
        
        # Progress bar with color coding
        progress_width = (posture_score / 100.0) * width
        if posture_score < 40:
            color = self.DANGER_RED
        elif posture_score < 70:
            color = self.WARNING_YELLOW
        else:
            color = self.SUCCESS_GREEN
        
        canvas.create_rectangle(0, bar_y, progress_width, bar_y + bar_height,
                               fill=color, outline=color)
        
        # Percentage text
        canvas.create_text(width // 2, bar_y + bar_height // 2,
                          text=f"{posture_score:.0f}%", font=("Arial", 10, "bold"),
                          fill="#ffffff")
        
        self.personal_posture_label.config(text=f"{posture_score:.0f} / 100")
    
    def _update_personal_session_timer(self) -> None:
        """Update session timer countdown."""
        if not self.current_session_id:
            return
        
        # Get session creation time
        self.session_manager.reload_from_disk()
        session = self.session_manager.sessions.get(self.current_session_id, {})
        
        if not session:
            return
        
        try:
            login_time = datetime.fromisoformat(session.get("login_time", ""))
        except (ValueError, TypeError):
            return
        
        now = datetime.now(login_time.tzinfo) if login_time.tzinfo else datetime.now()
        elapsed = (now - login_time).total_seconds()
        
        timeout_seconds = 600  # 10 minutes
        remaining = max(0, timeout_seconds - int(elapsed))
        
        minutes = remaining // 60
        seconds = remaining % 60
        
        timer_text = f"{minutes:02d}:{seconds:02d}"
        self.session_timer_label.config(text=timer_text)
        
        if remaining < 60:
            self.session_timer_label.config(fg=self.DANGER_RED)
            self.session_timer_warning.config(text="⚠️ Logging out soon!", fg=self.DANGER_RED)
        elif remaining < 120:
            self.session_timer_label.config(fg=self.WARNING_YELLOW)
            self.session_timer_warning.config(text="Less than 2 minutes left", fg=self.WARNING_YELLOW)
        else:
            self.session_timer_label.config(fg=self.ACCENT_BLUE)
            self.session_timer_warning.config(text="Session active", fg=self.SUCCESS_GREEN)
    
    def _update_personal_login_details(self, session: dict) -> None:
        """Update login details display."""
        login_time = session.get("login_time", "Unknown")
        self.personal_login_time_label.config(text=f"Login Time: {login_time}")
        
        ip = self.current_ip or "Unknown"
        self.personal_ip_label.config(text=f"IP Address: {ip}")
        
        # Geolocation
        # Geolocation (cached from background risk thread)
        geo_result = self._latest_geo_result or {}
        location = geo_result.get("country", "Unknown")
        self.personal_location_label.config(text=f"Location: {location}")
        
        # OS Info
        os_info = self.posture_checker.get_os_info()
        os_name = os_info.get("system", "Unknown")
        os_release = os_info.get("release", "")
        os_display = f"{os_name} {os_release}".strip()
        self.personal_os_label.config(text=f"Device OS: {os_display}")
    
    def _update_personal_connection_status(self) -> None:
        """Update VPN/Tor/Proxy connection status."""
        geo_result = self._latest_geo_result or {}
        
        # VPN
        if geo_result.get("is_proxy"):
            self.personal_vpn_badge.config(text="🔓 VPN: Yes (Flagged)", fg=self.DANGER_RED)
        else:
            self.personal_vpn_badge.config(text="🔒 VPN: No", fg=self.SUCCESS_GREEN)
        
        # Tor
        if geo_result.get("is_tor"):
            self.personal_tor_badge.config(text="⚠️  Tor: Yes (Blocked)", fg=self.DANGER_RED)
        else:
            self.personal_tor_badge.config(text="🛡  Tor: No", fg=self.SUCCESS_GREEN)
        
        # Hosting/Proxy
        if geo_result.get("is_hosting"):
            self.personal_proxy_badge.config(text="🌐 Proxy: Yes (Flagged)", fg=self.DANGER_RED)
        else:
            self.personal_proxy_badge.config(text="🌐 Proxy: No", fg=self.SUCCESS_GREEN)
    
    def _update_personal_alerts(self) -> None:
        """Update recent alerts for current user."""
        if not hasattr(self, "personal_alerts_text"):
            return
        
        self.session_manager.reload_from_disk()
        session = self.session_manager.sessions.get(self.current_session_id, {})
        
        events = session.get("events", [])
        alerts = [e for e in events if e.get("event_type") == "alert"]
        recent_alerts = alerts[-5:] if len(alerts) > 5 else alerts
        
        self.personal_alerts_text.config(state="normal")
        self.personal_alerts_text.delete(1.0, tk.END)
        
        if not recent_alerts:
            self.personal_alerts_text.insert(tk.END, "No alerts triggered during this session.")
        else:
            for alert in reversed(recent_alerts):
                timestamp = alert.get("timestamp", "Unknown")
                details = alert.get("details", {})
                severity = details.get("severity", "medium").upper() if isinstance(details, dict) else "MEDIUM"
                message = details.get("message", "Alert") if isinstance(details, dict) else str(details)
                
                severity_color = {
                    "CRITICAL": "red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(severity, "white")
                
                self.personal_alerts_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.personal_alerts_text.insert(tk.END, f"{severity}: {message}\n", severity_color)
        
        # Tag colors
        self.personal_alerts_text.tag_configure("timestamp", foreground="#7a7a7a", font=("Courier", 7))
        self.personal_alerts_text.tag_configure("red", foreground=self.DANGER_RED)
        self.personal_alerts_text.tag_configure("yellow", foreground=self.WARNING_YELLOW)
        self.personal_alerts_text.tag_configure("green", foreground=self.SUCCESS_GREEN)
        
        self.personal_alerts_text.config(state="disabled")
    
    def _rotate_security_tips(self) -> None:
        """Rotate security tips every 30 seconds."""
        if not hasattr(self, "personal_tip_text") or not hasattr(self, "security_tips"):
            return
        
        # Only update every 30 seconds
        if not hasattr(self, "last_tip_update"):
            self.last_tip_update = time.time()
        
        current_time = time.time()
        if current_time - self.last_tip_update < 30:
            return
        
        self.last_tip_update = current_time
        self.security_tips_index = (self.security_tips_index + 1) % len(self.security_tips)
        
        tip = self.security_tips[self.security_tips_index]
        
        self.personal_tip_text.config(state="normal")
        self.personal_tip_text.delete(1.0, tk.END)
        self.personal_tip_text.insert(tk.END, tip)
        self.personal_tip_text.config(state="disabled")
    
    def _update_personal_access_level(self) -> None:
        """Update accessible resources for user's role."""
        if not self.current_role:
            return
        
        # Get accessible apps for this role
        accessible = []
        for app_id, app_label, app_icon in self.PROTECTED_APPS:
            if self.rbac_manager.can_access(self.current_role, app_id):
                accessible.append(f"{app_icon} {app_label}")
        
        if accessible:
            access_text = "You can access: " + ", ".join(accessible)
        else:
            access_text = "You have limited access to protected resources."
        
        self.personal_access_label.config(text=access_text)

    # ================== AUTO REFRESH ==================
    
    def _start_auto_refresh(self) -> None:
        """Start periodic refresh of all tabs."""
        self._auto_refresh_loop()
    
    def _auto_refresh_loop(self) -> None:
        self._refresh_sessions()
        self._refresh_alerts()
        self._update_traffic_stats()
        
        # Schedule next refresh (5s for sessions/alerts; traffic stats each cycle)
        self.root.after(5000, self._auto_refresh_loop)


def main() -> None:
    root = tk.Tk()
    app = ZTNAApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
