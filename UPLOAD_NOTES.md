# Upload Notes

This folder is the GitHub-safe version of the project.

## Kept

- Source code under `main.py`, `gui/`, `mfa/`, `risk_engine/`, `device_posture/`, `session_manager/`, `threat_response/`, `traffic_monitor/`, `anomaly_detection/`, `rbac/`
- Core support files: `pdp.py`, `pep.py`, `logout.py`, `biometric_auth.py`
- Dependency list: `requirements.txt`
- Documentation: `README.md`, `EMAIL_SETUP.md`

## Removed or sanitized

- `.venv/`
- `build/`, `dist/`
- `__pycache__/`
- `*.pyc`, `*.pyo`, `*.pyd`
- `alerts_log.txt`
- `sessions_log.json.lock`
- `session_history_export.csv`
- Real `sessions_log.json` data
- Real `student_accounts.json` data
- Live `gmail_config.py` credentials
- `build_exe.py`
- `gui/ztna_gui_fixed.py`
- Empty stray `python` file

## Why

These items are either machine-specific, generated at runtime, duplicates, or can expose sensitive data.
