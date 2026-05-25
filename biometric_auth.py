"""Windows Hello fingerprint verification helpers for ZTNA Sentinel."""

from __future__ import annotations

import asyncio


LAST_BIOMETRIC_STATUS = "unknown"


async def _verify_fingerprint_async(purpose_message: str) -> bool:
    global LAST_BIOMETRIC_STATUS

    try:
        from winsdk.windows.security.credentials.ui import (
            UserConsentVerifier,
            UserConsentVerifierAvailability,
            UserConsentVerificationResult,
        )
    except ImportError:
        LAST_BIOMETRIC_STATUS = "skipped"
        print("Windows Hello library is not installed in this Python environment.")
        return False

    try:
        availability = await UserConsentVerifier.check_availability_async()
        if availability != UserConsentVerifierAvailability.AVAILABLE:
            LAST_BIOMETRIC_STATUS = "skipped"
            print("Windows Hello not available on this device, skipping biometric check")
            return False

        result = await UserConsentVerifier.request_verification_async(purpose_message)

        if result == UserConsentVerificationResult.VERIFIED:
            LAST_BIOMETRIC_STATUS = "verified"
            return True

        if result in (
            UserConsentVerificationResult.CANCELED,
            UserConsentVerificationResult.DEVICE_BUSY,
        ):
            LAST_BIOMETRIC_STATUS = "failed"
            return False

        if result == UserConsentVerificationResult.DEVICE_NOT_PRESENT:
            LAST_BIOMETRIC_STATUS = "skipped"
            return False

        LAST_BIOMETRIC_STATUS = "skipped"
        return False
    except Exception:
        LAST_BIOMETRIC_STATUS = "skipped"
        return False


def verify_fingerprint(username: str, purpose_message: str) -> bool:
    """Verify the user with Windows Hello fingerprint if available."""
    try:
        return asyncio.run(_verify_fingerprint_async(purpose_message))
    except Exception:
        global LAST_BIOMETRIC_STATUS
        LAST_BIOMETRIC_STATUS = "skipped"
        return False