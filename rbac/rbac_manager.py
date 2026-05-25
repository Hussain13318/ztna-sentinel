from typing import List


class RBACManager:
    """Simple role-based access control manager."""

    ROLE_PERMISSIONS = {
        "soc_operator": [
            "alerts_dashboard",
        ],
        "threat_analyst": [
            "alerts_dashboard",
            "traffic_log_viewer",
            "threat_report_generator",
            "session_management_console",
        ],
        "security_engineer": [
            "alerts_dashboard",
            "traffic_log_viewer",
            "threat_report_generator",
            "session_management_console",
            "ip_blacklist_manager",
            "policy_control_panel",
            "audit_log_exporter",
        ],
        "student": [],
        # Backward-compatible aliases for legacy role names already used elsewhere.
        "viewer": [
            "alerts_dashboard",
        ],
        "analyst": [
            "alerts_dashboard",
            "traffic_log_viewer",
            "threat_report_generator",
            "session_management_console",
        ],
        "admin": [
            "alerts_dashboard",
            "traffic_log_viewer",
            "threat_report_generator",
            "session_management_console",
            "ip_blacklist_manager",
            "policy_control_panel",
            "audit_log_exporter",
        ],
    }

    # Explicit student-portal capabilities (for privilege escalation detection).
    STUDENT_PORTAL_CAPABILITIES = {
        "student_dashboard_view",
        "student_courses_view",
        "student_course_detail",
        "student_course_download",
        "student_assignment_submit",
        "student_grades_view",
        "student_grade_review_request",
        "student_timetable_view",
        "student_timetable_export",
        "student_attendance_view",
        "student_attendance_relaxation_request",
        "student_campus_services_view",
        "student_portal_message_send",
        "student_portal_profile_update",
        "student_portal_fee_sim",
        "student_portal_library_reserve",
    }

    def can_access(self, role: str, application: str) -> bool:
        """Return True if role is allowed to access the application, else False."""
        normalized_role = (role or "").strip().lower()
        allowed_apps = self.ROLE_PERMISSIONS.get(normalized_role, [])
        return application in allowed_apps

    def list_allowed_apps(self, role: str) -> List[str]:
        """Return list of all allowed applications for the given role."""
        normalized_role = (role or "").strip().lower()
        return list(self.ROLE_PERMISSIONS.get(normalized_role, []))

    def student_may_use_capability(self, capability: str) -> bool:
        """Students may only use explicitly listed portal capabilities."""
        return capability in self.STUDENT_PORTAL_CAPABILITIES

    def is_staff_role(self, role: str) -> bool:
        r = (role or "").strip().lower()
        return r in {
            "soc_operator",
            "threat_analyst",
            "security_engineer",
            "viewer",
            "analyst",
            "admin",
        }


if __name__ == "__main__":
    rbac = RBACManager()

    print("Security Engineer apps:", rbac.list_allowed_apps("security_engineer"))
    print(
        "Can Threat Analyst access threat reports?",
        rbac.can_access("threat_analyst", "threat_report_generator"),
    )
    print(
        "Can SOC Operator access policy control panel?",
        rbac.can_access("soc_operator", "policy_control_panel"),
    )
