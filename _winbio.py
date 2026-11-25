"""
WINBIO Biometric Verification — ctypes bindings for Windows Biometric Framework.

Exposes:
  winbio_verify() -> bool   — opens a fingerprint session, prompts the user to scan,
                               returns True iff identity matches. Raises RuntimeError
                               with a specific message on failure (no sensor, no
                               enrollment, mismatch, cancellation, etc.).
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes

logger = logging.getLogger("humanver.winbio")

# ── DLL references ──────────────────────────────────────────────────────
_kernel32 = ctypes.windll.kernel32
_advapi = ctypes.windll.advapi32
_winbio = ctypes.windll.LoadLibrary("winbio.dll")

# ── Constants ────────────────────────────────────────────────────────────
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 0x00000001
WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_SUBTYPE_ANY = 0x00000000
WINBIO_IDENTITY_TYPE_SID = 3

TOKEN_QUERY = 0x0008
TOKEN_INFORMATION_CLASS_TOKEN_USER = 1  # TokenUser

S_OK = 0

# ── WinBio-specific HRESULT codes ──────────────────────────────────────
# Full list for proper error discrimination
WINBIO_E_UNKNOWN_ID = 0x80098005          # No enrollment for this user
WINBIO_E_NO_MATCH = 0x8009800B            # Fingerprint scanned but doesn't match
WINBIO_E_DEVICE_BUSY = 0x80098003         # Sensor is busy
WINBIO_E_INVALID_OPERATION = 0x8009801D   # No biometric unit available in session
WINBIO_E_CANCELED = 0x8009800B            # Operation was cancelled (by user/system)
WINBIO_E_ENROLLMENT_IN_PROGRESS = 0x80098014

# General Windows errors relevant to WinBio calls
E_INVALIDARG = 0x80070057
E_ACCESSDENIED = 0x80070005
WINBIO_E_NOT_ACTIVATED = 0x8009800C       # Biometric service not activated

# ── ctypes types ─────────────────────────────────────────────────────────
UCHAR = ctypes.c_ubyte
BOOLEAN = ctypes.c_byte


class _WINBIO_IDENTITY_U(ctypes.Union):
    _fields_ = [
        ("Null", wintypes.ULONG * 4),
        ("PoolId", wintypes.ULONG * 4),
        ("Sid", UCHAR * 68),
        ("TemplateId", wintypes.ULONG * 8),
        ("Upn", wintypes.WCHAR * 256),
    ]


class WINBIO_IDENTITY(ctypes.Structure):
    _fields_ = [("Type", wintypes.ULONG), ("_u", _WINBIO_IDENTITY_U)]


class WINBIO_VERIFY_RESULT(ctypes.Structure):
    _fields_ = [("Match", BOOLEAN), ("SubFactor", UCHAR)]


# ── WINBIO function prototypes ───────────────────────────────────────────
_winbio.WinBioOpenSession.argtypes = [
    wintypes.ULONG,      # dwType
    wintypes.ULONG,      # dwPoolType
    wintypes.ULONG,      # dwFlags
    ctypes.c_void_p,     # pTargetWindowHandle (HWND)
    wintypes.UINT,       # dwTargetWindowMessage
    ctypes.c_void_p,     # pAppWindowHandle (HWND)
    ctypes.POINTER(wintypes.HANDLE),  # SessionHandle
]
_winbio.WinBioOpenSession.restype = wintypes.HRESULT

_winbio.WinBioCloseSession.argtypes = [wintypes.HANDLE]
_winbio.WinBioCloseSession.restype = wintypes.HRESULT

_winbio.WinBioVerify.argtypes = [
    wintypes.HANDLE,                     # SessionHandle
    ctypes.POINTER(WINBIO_IDENTITY),     # Identity (optional — may be NULL)
    UCHAR,                               # SubFactor
    ctypes.c_void_p,                     # Payload (optional WINBIO_BIR *)
    ctypes.POINTER(WINBIO_VERIFY_RESULT),  # VerifyResult
]
_winbio.WinBioVerify.restype = wintypes.HRESULT


# ── helpers ──────────────────────────────────────────────────────────────

def _get_current_user_sid_bytes() -> bytes:
    """Return the current user's SID as a bytes object.

    Copies the SID data into a Python bytes object while the source buffer
    is still alive, avoiding the dangling-pointer bug of the earlier version
    that returned a raw ctypes pointer into a local buffer.
    """
    token = wintypes.HANDLE()
    if not _advapi.OpenProcessToken(
        wintypes.HANDLE(_kernel32.GetCurrentProcess()),
        wintypes.DWORD(TOKEN_QUERY),
        ctypes.byref(token),
    ):
        raise RuntimeError("Failed to open process token", ctypes.WinError())

    try:
        buf_size = wintypes.DWORD(0)
        _advapi.GetTokenInformation(
            token,
            wintypes.DWORD(TOKEN_INFORMATION_CLASS_TOKEN_USER),
            None, 0, ctypes.byref(buf_size),
        )
        buf = ctypes.create_string_buffer(buf_size.value)
        if not _advapi.GetTokenInformation(
            token,
            wintypes.DWORD(TOKEN_INFORMATION_CLASS_TOKEN_USER),
            buf, buf_size.value, ctypes.byref(buf_size),
        ):
            raise RuntimeError("GetTokenInformation failed", ctypes.WinError())

        # TOKEN_USER → SID_AND_ATTRIBUTES → PSID (first pointer-sized field)
        sid_ptr = ctypes.cast(
            ctypes.addressof(buf), ctypes.POINTER(ctypes.c_void_p)
        ).contents.value

        _advapi.GetLengthSid.restype = wintypes.DWORD
        _advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
        sid_len = _advapi.GetLengthSid(sid_ptr)

        # Copy SID data while buf is still alive
        sid_data = (ctypes.c_ubyte * sid_len).from_address(sid_ptr)
        return bytes(sid_data)
    finally:
        _kernel32.CloseHandle(token)


def _build_identity(sid_bytes: bytes) -> WINBIO_IDENTITY:
    """Build a WINBIO_IDENTITY from raw SID bytes."""
    identity = WINBIO_IDENTITY()
    identity.Type = WINBIO_IDENTITY_TYPE_SID
    ctypes.memmove(identity._u.Sid, sid_bytes, len(sid_bytes))
    return identity


_WINBIO_ERROR_MESSAGES: dict[int, str] = {
    WINBIO_E_UNKNOWN_ID: (
        "Geen vingerafdruk geregistreerd voor deze gebruiker.\n"
        "Registreer een vingerafdruk via Instellingen → Accounts → Aanmeldingsopties."
    ),
    WINBIO_E_NO_MATCH: "Vingerafdruk komt niet overeen. Probeer opnieuw.",
    WINBIO_E_DEVICE_BUSY: "Vingerafdruksensor is bezet. Probeer het later opnieuw.",
    WINBIO_E_INVALID_OPERATION: (
        "Geen vingerafdruksensor beschikbaar.\n"
        "De Windows Biometric Framework heeft geen fingerprint unit gevonden."
    ),
    WINBIO_E_ENROLLMENT_IN_PROGRESS: "Er is al een registratie bezig. Voltooi die eerst.",
    WINBIO_E_NOT_ACTIVATED: "Windows Biometric Service is niet geactiveerd.",
    E_INVALIDARG: (
        "Vingerafdruk verificatie niet beschikbaar.\n"
        "De Windows Biometric Framework heeft geen compatibele sensor gevonden "
        "of kan geen verificatie starten op dit systeem."
    ),
    E_ACCESSDENIED: (
        "Geen toegang tot de biometrische sensor.\n"
        "Voer Hermes uit als administrator of controleer de beveiligingsinstellingen."
    ),
}


def _hresult_to_message(hr: int) -> str:
    """Translate a WinBio HRESULT to a user-facing message."""
    msg = _WINBIO_ERROR_MESSAGES.get(hr)
    if msg:
        return msg
    return f"Verificatie mislukt (foutcode 0x{hr:08X})."


# ── public API ───────────────────────────────────────────────────────────

def winbio_verify(timeout_ms: int = 30000) -> bool:
    """Open a fingerprint session and prompt the user to scan.

    Does NOT pre-check for sensor availability — lets the WinBio API
    itself report the actual error. This way a working sensor is tried
    even when WinBioEnumBiometricUnits returns 0 units (which can happen
    on some Windows configurations despite a functioning sensor).

    Returns True when the fingerprint matches the current user's identity.
    Raises RuntimeError with a descriptive message on failure.
    """
    # Get SID for current user (copied as bytes to avoid dangling pointer)
    sid_bytes = _get_current_user_sid_bytes()

    # Build identity struct
    identity = _build_identity(sid_bytes)

    # Open session
    session = wintypes.HANDLE()
    hr = _winbio.WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,
        WINBIO_POOL_SYSTEM,
        WINBIO_FLAG_DEFAULT,
        None, 0, None,
        ctypes.byref(session),
    )
    if hr != S_OK:
        raise RuntimeError(
            "Kon geen biometrische sessie openen. "
            f"HRESULT=0x{ctypes.c_uint32(hr).value:08X}"
        )

    try:
        # Verify — synchronous, shows Windows Hello dialog
        result = WINBIO_VERIFY_RESULT()
        hr = _winbio.WinBioVerify(
            session, ctypes.byref(identity),
            WINBIO_SUBTYPE_ANY, None,
            ctypes.byref(result),
        )
        if hr == S_OK:
            return bool(result.Match)
        else:
            err_code = ctypes.c_uint32(hr).value
            raise RuntimeError(_hresult_to_message(err_code))
    finally:
        _winbio.WinBioCloseSession(session)