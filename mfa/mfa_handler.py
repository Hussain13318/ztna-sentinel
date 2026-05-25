import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class MFAHandler:
    """Handles TOTP-based MFA operations for users with email OTP delivery."""

    def __init__(self, sender_email: str = None, sender_password: str = None) -> None:
        # In-memory store for user secrets for simulation purposes.
        self.user_secrets: dict[str, str] = {}
        # Keep OTP valid long enough for email delivery and user entry.
        self.otp_interval_seconds = 120
        
        # Gmail credentials for sending OTP emails
        self.sender_email = sender_email or "your-email@gmail.com"
        self.sender_password = sender_password or "your-app-password"
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587

    def generate_secret_for_user(self, user_id: str) -> str:
        """Generate and store a unique TOTP secret for a user."""
        secret = pyotp.random_base32()
        self.user_secrets[user_id] = secret
        return secret

    def generate_otp(self, user_id: str) -> str:
        """Generate a 6-digit OTP for the given user."""
        if user_id not in self.user_secrets:
            self.generate_secret_for_user(user_id)

        totp = pyotp.TOTP(
            self.user_secrets[user_id],
            digits=6,
            interval=self.otp_interval_seconds,
        )
        return totp.now()

    def send_otp_via_email(self, user_email: str, otp: str) -> bool:
        """Send OTP to user's email via Gmail SMTP."""
        try:
            # Create message
            message = MIMEMultipart()
            message["From"] = self.sender_email
            message["To"] = user_email
            message["Subject"] = "Your ZTNA Security OTP Code"
            
            # Email body
            body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="background-color: #ffffff; border-radius: 8px; padding: 30px; max-width: 500px; margin: auto;">
                        <h2 style="color: #333;">ZTNA Security Framework</h2>
                        <p style="color: #666; font-size: 14px;">Your One-Time Password (OTP) for login:</p>
                        
                        <div style="background-color: #f0f0f0; border-left: 4px solid #4f9cf9; padding: 15px; margin: 20px 0; border-radius: 4px;">
                            <h1 style="color: #4f9cf9; letter-spacing: 3px; margin: 0;">{otp}</h1>
                        </div>
                        
                        <p style="color: #999; font-size: 12px;">
                            This OTP will expire in 2 minutes. Do not share this code with anyone.<br>
                            If you did not request this code, please ignore this email.
                        </p>
                        
                        <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                        <p style="color: #999; font-size: 11px; text-align: center;">
                            ZTNA Security Framework | Air University
                        </p>
                    </div>
                </body>
            </html>
            """
            
            message.attach(MIMEText(body, "html"))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
            
            print(f"[MFA] OTP sent successfully to {user_email}")
            return True
            
        except Exception as e:
            print(f"[MFA] Failed to send OTP email: {e}")
            print(f"[MFA] Make sure to configure Gmail credentials in the MFA handler")
            return False

    def send_otp(self, user_id: str, user_email: str = None) -> str:
        """Generate OTP and send it via email."""
        otp = self.generate_otp(user_id)
        
        if user_email:
            # Try to send via email
            self.send_otp_via_email(user_email, otp)
        else:
            # Fallback: print to console
            print(f"[MFA] OTP for '{user_id}': {otp}")
        
        return otp

    def verify_otp(self, user_id: str, entered_otp: str) -> bool:
        """Verify entered OTP and return True/False for auth result."""
        secret = self.user_secrets.get(user_id)
        if not secret:
            return False

        normalized_otp = (entered_otp or "").strip()
        if not normalized_otp.isdigit() or len(normalized_otp) != 6:
            return False

        totp = pyotp.TOTP(
            secret,
            digits=6,
            interval=self.otp_interval_seconds,
        )
        return bool(totp.verify(normalized_otp))


if __name__ == "__main__":
    # Simple local demo
    mfa = MFAHandler()
    user = "user_001"

    mfa.generate_secret_for_user(user)
    mfa.send_otp(user)

    user_input = input("Enter OTP: ").strip()
    result = mfa.verify_otp(user, user_input)
    print("Authentication result:", result)
