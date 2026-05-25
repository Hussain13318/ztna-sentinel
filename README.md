# ZTNA Sentinel - GitHub Upload

This folder is a cleaned, GitHub-safe copy of the project.

## What is included

- `main.py`
- `gui/`
- `biometric_auth.py`
- `device_posture/`
- `risk_engine/`
- `mfa/`
- `rbac/`
- `session_manager/`
- `threat_response/`
- `traffic_monitor/`
- `anomaly_detection/`
- `logout.py`
- `pdp.py`
- `pep.py`
- `requirements.txt`

## Safe placeholders

- `gmail_config.py` contains blank values only.
- `sessions_log.json` starts empty.
- `student_accounts.json` starts empty.
- `requirements.txt` excludes the standard-library `datetime` entry.

## Run

```powershell
python -m pip install -r requirements.txt
python main.py
```

If you use a virtual environment locally, create it on your own machine and do not upload it.

# ZTNA Framework - GUI Application

## Overview
AI-Based Adaptive Hybrid Zero Trust Network Access (ZTNA) Framework with Tkinter Desktop GUI

## Features

### 🔐 Tab 1: Login Panel
- Username, password, and role input (admin/analyst/viewer)
- OTP-based Multi-Factor Authentication
- Automatic device posture check after MFA
- Real-time risk scoring with color-coded display:
  - 🟢 GREEN = LOW risk
  - 🟡 YELLOW = MEDIUM risk
  - 🔴 RED = HIGH risk
- Access granted/denied decision display

### 📊 Tab 2: Active Sessions
- Real-time table of all active sessions
- Displays: Session ID, Username, Role, IP, Risk Score, Risk Level, Status
- Color-coded rows by risk level
- Manual session blocking capability
- Auto-refreshes every 10 seconds

### ⚠️ Tab 3: Alerts & Threats
- Scrollable alert feed with timestamps
- Color-coded by severity (info/medium/high/critical)
- Alert counter showing total alerts
- Clear alerts functionality

### 📡 Tab 4: Traffic Monitor
- Live packet capture statistics
- Packets per second counter
- Total data transferred (MB)
- Suspicious pattern detection flags
- Last 20 captured packet details
- Start/Stop monitoring controls
- Updates every 2 seconds

### 📜 Tab 5: Session History
- Complete session history from sessions_log.json
- Session replay with step-by-step event viewer
- Export to CSV functionality
- Searchable session records

## Installation

1. Navigate to project folder:
```bash
D:\Air universty\4th Semester\Projects\NS --- Project\Git upload.
```

2. Create virtual environment (optional but recommended):
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # On Windows
```

If you get execution policy error, run:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Or use the venv Python directly without activation:
```bash
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

### Using Virtual Environment:
```bash
.\.venv\Scripts\python.exe main.py
```

### Using System Python:
```bash
python main.py
```

## Usage Instructions

1. **Launch the GUI**: Run `python main.py`

2. **Login Process**:
   - Enter username and password
   - Select role (admin/analyst/viewer)
   - Click "Login" button
   - Check console/terminal for generated OTP
   - Enter OTP and click "Verify OTP"
   - Wait for device posture check to complete
   - View risk score and access decision

3. **Monitor Sessions**:
   - Switch to "Active Sessions" tab
   - View all live sessions
   - Select and block suspicious sessions

4. **Check Alerts**:
   - Switch to "Alerts" tab
   - Review security events and threats
   - Clear alerts when needed

5. **Traffic Monitoring**:
   - Switch to "Traffic Monitor" tab
   - Click "Start Monitoring" (requires Admin privileges)
   - View live packet statistics
   - Click "Stop Monitoring" when done

6. **Session History**:
   - Switch to "History" tab
   - Select any past session
   - Click "Replay Session" to see detailed event log
   - Click "Export to CSV" to save history

## Important Notes

- **Administrator Privileges**: Traffic monitoring with Scapy requires running the application as Administrator on Windows
- **OTP Display**: Generated OTPs are printed to the console/terminal window
- **Auto-Refresh**: Sessions and alerts auto-refresh every 10 seconds, traffic stats every 2 seconds
- **Session Persistence**: All sessions are logged to `sessions_log.json`
- **Dark Theme**: Application uses a dark color scheme optimized for security monitoring

## Troubleshooting

### "Module not found" errors:
```bash
pip install -r requirements.txt
```

### Traffic monitoring not working:
- Run terminal/PowerShell as Administrator
- Ensure Npcap or WinPcap is installed (for Scapy on Windows)

### GUI doesn't appear:
- Check if tkinter is installed: `python -m tkinter`
- On Linux, install: `sudo apt-get install python3-tk`

### Permission errors on virtual environment:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## Project Structure

```
co pilot project/
├── main.py                    # GUI launcher
├── requirements.txt           # Dependencies
├── sessions_log.json         # Session history (auto-generated)
├── gui/
│   ├── __init__.py
│   └── ztna_gui.py           # Main GUI application
├── mfa/                      # Multi-Factor Authentication
├── device_posture/           # Device health checker
├── risk_engine/              # Dynamic risk scoring
├── rbac/                     # Role-Based Access Control
├── traffic_monitor/          # Network traffic capture
├── anomaly_detection/        # AI-based anomaly detection
├── threat_response/          # Automated response system
└── session_manager/          # Session logging & management
```

## Technologies Used

- **Python 3.10+**
- **Tkinter/ttk**: Desktop GUI framework
- **Flask**: Web dashboard (not needed for GUI)
- **Scapy**: Packet capture
- **pyotp**: TOTP-based MFA
- **LangChain**: AI anomaly detection
- **psutil**: Device metrics

## Security Features

✅ Multi-factor authentication (OTP)  
✅ Device posture validation  
✅ Dynamic risk scoring  
✅ Role-based access control  
✅ Real-time traffic monitoring  
✅ AI-powered anomaly detection  
✅ Automated threat response  
✅ Session audit logging  

## License

Academic Project - Air University, 4th Semester

## Support

For issues or questions, refer to the project documentation or contact the development team.
