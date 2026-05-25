# ZTNA Email OTP Setup Guide

## Overview
The ZTNA system now sends One-Time Password (OTP) codes directly to users' email addresses instead of displaying them in popups.

## Setup Instructions

### Step 1: Prepare Your Gmail Account

1. Go to **https://myaccount.google.com/**
2. Click on **"Security"** in the left sidebar
3. Scroll down to **"2-Step Verification"**
   - If not enabled, click to enable it and follow Google's steps
4. Once 2-Step Verification is enabled, go to **https://myaccount.google.com/apppasswords**
5. Select:
   - **App**: Mail
   - **Device**: Windows Computer (or your device type)
6. Google will generate a **16-character password** (with spaces)
   - Example: `xxxx xxxx xxxx xxxx`
7. **Copy this password** (keep it safe!)

### Step 2: Configure ZTNA

1. Open the file: `gmail_config.py` in the main ZTNA directory
2. Replace `your-email@gmail.com` with your Gmail address
3. Replace `xxxx xxxx xxxx xxxx` with the 16-character app password you copied
4. Save the file

### Step 3: Test the Setup

1. Run the ZTNA GUI:
   ```bash
   python main.py
   ```

2. On the Login tab, fill in:
   - **Username**: Any test username (e.g., `testuser`)
   - **Email**: The Gmail address you configured (e.g., `your-email@gmail.com`)
   - **Password**: Any password
   - **Role**: admin/analyst/viewer

3. Click **"Login"**

4. You should see a message: `"An OTP code has been sent to: your-email@gmail.com"`

5. **Check your Gmail inbox** - you should receive an email with the OTP code

6. Enter the OTP in the textbox below and click **"Verify OTP"**

### Step 4: Troubleshooting

**Email not received?**
- Check spam/junk folder
- Make sure you copied the **app password** correctly (16 characters with spaces)
- Make sure the email address in the login form matches the Gmail account

**"Failed to send OTP email" message in console?**
- Check that `gmail_config.py` has correct email and password
- Make sure 2-Step Verification is enabled on your Google account
- App password must be the 16-character one from `https://myaccount.google.com/apppasswords`

**Port/Connection errors?**
- Make sure your system allows SMTP connections (port 587)
- Some networks block outgoing email - try on a different network or use VPN

### Important Security Notes

⚠️ **Never share your app password!** 
- This password grants access to send emails from your account
- Keep `gmail_config.py` private
- If you suspect compromise, revoke the app password and generate a new one

⚠️ **Do NOT use your regular Gmail password**
- Use the special 16-character **app password** only
- Regular passwords won't work with this setup

## How It Works

1. User enters email during login
2. System generates a 6-digit OTP code
3. OTP is sent to the user's email via Gmail SMTP
4. User retrieves OTP from email
5. User enters OTP to complete authentication
6. OTP is verified and access is granted/denied based on risk assessment

---

**Questions?** Check the email template in `mfa/mfa_handler.py` for customization options.
