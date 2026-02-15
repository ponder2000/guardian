"""
Guardian License Daemon - Python Client SDK

A full-featured Python client for communicating with the Guardian license
daemon over a Unix domain socket using a binary protocol with mutual
authentication and AES-256-GCM encrypted messaging.

Requirements:
    pip install msgpack cryptography

Protocol overview:
    Wire format: [4 bytes uint32 BE total_length][1 byte msg_type][N bytes payload]
    where total_length = 1 + len(payload).

    Handshake:
        1. Connect to Unix socket
        2. Read GUARDIAN_HELLO, verify daemon Ed25519 signature
        3. Generate client nonce, compute HMAC, send SERVICE_AUTH
        4. Read AUTH_RESULT, confirm status == "ok"
        5. Derive session key via HMAC-SHA256
        6. All subsequent messages are AES-256-GCM encrypted

Usage:
    from guardian_client import GuardianClient

    def on_valid(details):
        print(f"License valid for {details.module}")

    def on_invalid(details, error):
        print(f"License invalid: {error}")

    client = GuardianClient(
        module="my-module",
        valid_handler=on_valid,
        invalid_handler=on_invalid,
    )
    client.start()
    # ... application runs ...
    client.stop()
"""

from __future__ import annotations

import hmac as _hmac
import hashlib
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import msgpack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

__all__ = [
    "GuardianClient",
    "LicenseDetails",
    "StatusInfo",
    "check_status",
    "GuardianError",
    "GuardianConnectionError",
    "GuardianAuthError",
    "GuardianProtocolError",
    "GuardianLicenseError",
]

logger = logging.getLogger("guardian_client")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_MESSAGE_SIZE = 1 << 20  # 1 MiB

# Message types
_MSG_GUARDIAN_HELLO = 0x01
_MSG_SERVICE_AUTH = 0x02
_MSG_AUTH_RESULT = 0x03
_MSG_LICENSE_REQUEST = 0x04
_MSG_LICENSE_RESPONSE = 0x05
_MSG_HEARTBEAT_PING = 0x06
_MSG_HEARTBEAT_PONG = 0x07
_MSG_STATUS_REQUEST = 0x09
_MSG_STATUS_RESPONSE = 0x0A

_CLIENT_NONCE_SIZE = 32
_AES_GCM_NONCE_SIZE = 12
_SESSION_KEY_SUFFIX = b"guardian-session-v1"

_DEFAULT_SOCKET_PATH = "/var/run/guardian/guardian.sock"
_DEFAULT_TOKEN_PATH = "/etc/guardian/token"
_DEFAULT_CHECK_INTERVAL = 300  # seconds


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GuardianError(Exception):
    """Base exception for all Guardian client errors."""


class GuardianConnectionError(GuardianError):
    """Raised when the client cannot connect to the daemon."""


class GuardianAuthError(GuardianError):
    """Raised when authentication with the daemon fails."""


class GuardianProtocolError(GuardianError):
    """Raised on wire-protocol violations (unexpected message types, bad frames)."""


class GuardianLicenseError(GuardianError):
    """Raised when a license check fails."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LicenseDetails:
    """Aggregated license and daemon status returned by checks and heartbeats.

    Attributes:
        valid: Whether the license is currently valid for the requested module.
        module: The module name that was checked.
        expires_at: ISO-8601 expiry timestamp string from the license response.
        features: List of feature strings enabled by the license.
        metadata: Arbitrary key/value metadata associated with the license.
        hw_status: Hardware status reported by the daemon heartbeat.
        license_status: Overall license status reported by the daemon heartbeat.
        expires_in_days: Number of days until the license expires, from heartbeat.
    """

    valid: bool = False
    module: str = ""
    expires_at: str = ""
    features: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    hw_status: str = ""
    license_status: str = ""
    expires_in_days: int = 0


@dataclass
class StatusInfo:
    """Result of an anonymous status check against the Guardian daemon.

    Contains only non-sensitive operational health data.  No module names,
    features, license IDs, customer info, or hardware fingerprint values
    are exposed.

    Attributes:
        status: Overall daemon status ("ok" or "error").
        hw_status: Hardware binding status.
        license_status: License status ("ok" or "expired").
        expires_in_days: Days until the license expires.
        daemon_version: Daemon build version string.
        uptime: Seconds since the daemon started.
    """

    status: str = ""
    hw_status: str = ""
    license_status: str = ""
    expires_in_days: int = 0
    daemon_version: str = ""
    uptime: int = 0


# ---------------------------------------------------------------------------
# Anonymous status check
# ---------------------------------------------------------------------------


def check_status(
    socket_path: str = _DEFAULT_SOCKET_PATH,
    timeout: float = 5.0,
) -> StatusInfo:
    """Perform an anonymous status check against the Guardian daemon.

    Connects to the daemon, reads the hello message (without verifying the
    signature), sends a ``STATUS_REQUEST``, reads the ``STATUS_RESPONSE``,
    and closes the connection.  No token file or authentication is required.

    Args:
        socket_path: Path to the Guardian Unix domain socket.
        timeout: Socket timeout in seconds (default 5).

    Returns:
        A populated :class:`StatusInfo` instance.

    Raises:
        GuardianConnectionError: If the daemon is unreachable.
        GuardianProtocolError: On wire-protocol violations.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(socket_path)
        except OSError as exc:
            raise GuardianConnectionError(
                f"cannot connect to {socket_path}: {exc}"
            ) from exc

        # Read GUARDIAN_HELLO (skip signature verification — anonymous).
        msg_type, _payload = _read_message(sock)
        if msg_type != _MSG_GUARDIAN_HELLO:
            raise GuardianProtocolError(
                f"expected GUARDIAN_HELLO (0x{_MSG_GUARDIAN_HELLO:02x}), "
                f"got 0x{msg_type:02x}"
            )

        # Send STATUS_REQUEST (empty payload).
        _write_message(sock, _MSG_STATUS_REQUEST, {})

        # Read STATUS_RESPONSE.
        msg_type, payload = _read_message(sock)
        if msg_type != _MSG_STATUS_RESPONSE:
            raise GuardianProtocolError(
                f"expected STATUS_RESPONSE (0x{_MSG_STATUS_RESPONSE:02x}), "
                f"got 0x{msg_type:02x}"
            )

        resp = msgpack.unpackb(payload, raw=False)
        return StatusInfo(
            status=resp.get("status", ""),
            hw_status=resp.get("hw_status", ""),
            license_status=resp.get("license_status", ""),
            expires_in_days=int(resp.get("expires_in_days", 0)),
            daemon_version=resp.get("daemon_version", ""),
            uptime=int(resp.get("uptime", 0)),
        )
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Token file parser
# ---------------------------------------------------------------------------


@dataclass
class _TokenFileCredentials:
    service_id: str = ""
    token: bytes = b""
    daemon_pub: bytes = b""


def _parse_token_file(path: str) -> _TokenFileCredentials:
    """Parse an INI-style Guardian token file.

    Expected format::

        SERVICE_ID=service_A
        TOKEN=tok_<hex>
        DAEMON_PUB=dpub_<hex>

    Lines starting with ``#`` and blank lines are ignored.

    Raises:
        GuardianAuthError: If the file is missing, unreadable, or lacks
            required fields.
    """
    try:
        with open(path, "r") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise GuardianAuthError(f"cannot read token file {path}: {exc}") from exc

    creds = _TokenFileCredentials()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        if key == "SERVICE_ID":
            creds.service_id = value
        elif key == "TOKEN":
            hex_str = value.removeprefix("tok_")
            try:
                creds.token = bytes.fromhex(hex_str)
            except ValueError as exc:
                raise GuardianAuthError(
                    f"invalid TOKEN hex in token file: {exc}"
                ) from exc
        elif key == "DAEMON_PUB":
            hex_str = value.removeprefix("dpub_")
            try:
                creds.daemon_pub = bytes.fromhex(hex_str)
            except ValueError as exc:
                raise GuardianAuthError(
                    f"invalid DAEMON_PUB hex in token file: {exc}"
                ) from exc

    if not creds.service_id:
        raise GuardianAuthError("missing SERVICE_ID in token file")
    if not creds.token:
        raise GuardianAuthError("missing TOKEN in token file")
    if not creds.daemon_pub:
        raise GuardianAuthError("missing DAEMON_PUB in token file")

    return creds


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------


def _hmac_sha256(message: bytes, key: bytes) -> bytes:
    """Compute HMAC-SHA256(message, key)."""
    return _hmac.new(key, message, hashlib.sha256).digest()


def _verify_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True on success, False on failure."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _derive_session_key(
    guardian_nonce: bytes, client_nonce: bytes, token: bytes
) -> bytes:
    """Derive the AES-256-GCM session key.

    Formula: HMAC-SHA256(guardian_nonce || client_nonce, token || "guardian-session-v1")
    """
    message = guardian_nonce + client_nonce
    key = token + _SESSION_KEY_SUFFIX
    return _hmac_sha256(message, key)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext+tag
    """
    nonce = os.urandom(_AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def _aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-GCM.  *data* is nonce (12 bytes) || ciphertext+tag."""
    if len(data) < _AES_GCM_NONCE_SIZE:
        raise GuardianProtocolError("encrypted payload too short for nonce")
    nonce = data[:_AES_GCM_NONCE_SIZE]
    ct = data[_AES_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as exc:
        raise GuardianProtocolError(f"AES-GCM decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Wire-protocol helpers
# ---------------------------------------------------------------------------


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*.

    Raises:
        GuardianConnectionError: On premature EOF or socket error.
    """
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError as exc:
            raise GuardianConnectionError(
                f"socket read error: {exc}"
            ) from exc
        if not chunk:
            raise GuardianConnectionError(
                f"connection closed (read {len(buf)} of {n} bytes)"
            )
        buf.extend(chunk)
    return bytes(buf)


def _read_message(sock: socket.socket) -> tuple[int, bytes]:
    """Read a single framed message from the socket.

    Returns:
        (msg_type, payload_bytes)

    Raises:
        GuardianProtocolError: On framing violations.
        GuardianConnectionError: On I/O errors.
    """
    header = _recv_exact(sock, 4)
    total_len = struct.unpack("!I", header)[0]

    if total_len > _MAX_MESSAGE_SIZE:
        raise GuardianProtocolError(
            f"message too large: {total_len} bytes exceeds max {_MAX_MESSAGE_SIZE}"
        )
    if total_len < 1:
        raise GuardianProtocolError(f"message too short: {total_len} bytes")

    type_byte = _recv_exact(sock, 1)
    msg_type = type_byte[0]

    payload_len = total_len - 1
    payload = _recv_exact(sock, payload_len) if payload_len > 0 else b""

    return msg_type, payload


def _write_message(sock: socket.socket, msg_type: int, payload: Any) -> None:
    """Encode *payload* with msgpack and write a framed message.

    Raises:
        GuardianProtocolError: If the resulting frame exceeds the max size.
        GuardianConnectionError: On I/O errors.
    """
    data = msgpack.packb(payload, use_bin_type=True)
    total_len = 1 + len(data)
    if total_len > _MAX_MESSAGE_SIZE:
        raise GuardianProtocolError(
            f"message too large: {total_len} bytes exceeds max {_MAX_MESSAGE_SIZE}"
        )

    frame = struct.pack("!I", total_len) + bytes([msg_type]) + data
    try:
        sock.sendall(frame)
    except OSError as exc:
        raise GuardianConnectionError(f"socket write error: {exc}") from exc


def _write_encrypted_message(
    sock: socket.socket, msg_type: int, payload: Any, session_key: bytes
) -> None:
    """Encrypt and write a framed message.

    Inner format (before encryption):
        [1-byte msg_type][msgpack-encoded payload]

    The encrypted blob (nonce || ciphertext+tag) is then wrapped in the
    standard wire frame with the same msg_type as the outer type byte.
    """
    data = msgpack.packb(payload, use_bin_type=True)
    inner = bytes([msg_type]) + data
    encrypted = _aes_gcm_encrypt(session_key, inner)

    total_len = 1 + len(encrypted)
    if total_len > _MAX_MESSAGE_SIZE:
        raise GuardianProtocolError(
            f"encrypted message too large: {total_len} bytes exceeds max "
            f"{_MAX_MESSAGE_SIZE}"
        )

    frame = struct.pack("!I", total_len) + bytes([msg_type]) + encrypted
    try:
        sock.sendall(frame)
    except OSError as exc:
        raise GuardianConnectionError(f"socket write error: {exc}") from exc


def _read_encrypted_message(
    sock: socket.socket, session_key: bytes
) -> tuple[int, dict]:
    """Read a framed message, decrypt, and return the inner type and decoded payload.

    Returns:
        (inner_msg_type, decoded_payload_dict)
    """
    _outer_type, encrypted = _read_message(sock)
    plaintext = _aes_gcm_decrypt(session_key, encrypted)

    if len(plaintext) < 1:
        raise GuardianProtocolError("decrypted payload is empty")

    inner_type = plaintext[0]
    inner_data = plaintext[1:]
    decoded = msgpack.unpackb(inner_data, raw=False)
    return inner_type, decoded


# ---------------------------------------------------------------------------
# Main client class
# ---------------------------------------------------------------------------


class GuardianClient:
    """Client SDK for the Guardian license daemon.

    Connects to the daemon over a Unix domain socket, performs mutual
    authentication, and provides license checking with periodic heartbeats
    in a background thread.

    Parameters:
        module: The license module name to check.
        socket_path: Path to the daemon Unix socket.  Falls back to the
            ``GUARDIAN_SOCKET`` environment variable, then to
            ``/var/run/guardian/guardian.sock``.
        token_path: Path to the service token credential file.  Falls back
            to ``GUARDIAN_TOKEN_PATH``, then to ``/etc/guardian/token``.
        check_interval: Seconds between periodic heartbeat/license checks
            (default 300).
        valid_handler: Callback ``(details: LicenseDetails) -> None`` invoked
            when a license check succeeds.
        invalid_handler: Callback ``(details: LicenseDetails, error: str) -> None``
            invoked when a license check fails.

    Thread safety:
        All public methods are safe to call from any thread.  Internal
        socket I/O is serialized via a reentrant lock.
    """

    def __init__(
        self,
        module: str,
        socket_path: Optional[str] = None,
        token_path: Optional[str] = None,
        check_interval: int = _DEFAULT_CHECK_INTERVAL,
        valid_handler: Optional[Callable[[LicenseDetails], None]] = None,
        invalid_handler: Optional[Callable[[LicenseDetails, str], None]] = None,
    ) -> None:
        # Configuration
        self._module = module
        self._socket_path = (
            socket_path
            or os.environ.get("GUARDIAN_SOCKET")
            or _DEFAULT_SOCKET_PATH
        )
        self._token_path = (
            token_path
            or os.environ.get("GUARDIAN_TOKEN_PATH")
            or _DEFAULT_TOKEN_PATH
        )
        self._check_interval = max(1, check_interval)
        self._valid_handler = valid_handler
        self._invalid_handler = invalid_handler

        # Connection state (guarded by _lock)
        self._lock = threading.RLock()
        self._sock: Optional[socket.socket] = None
        self._session_key: Optional[bytes] = None
        self._session_id: str = ""

        # Cached credentials (parsed once, reused on reconnect)
        self._creds: Optional[_TokenFileCredentials] = None

        # Background thread state
        self._checker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._started = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Connect, authenticate, perform initial license check, and start
        the periodic background checker thread.

        Raises:
            GuardianConnectionError: If the daemon is unreachable.
            GuardianAuthError: If authentication fails.
            GuardianLicenseError: If the initial license check fails and no
                *invalid_handler* is set.
        """
        with self._lock:
            if self._started:
                raise GuardianError("client is already started")

            self._connect()
            self._initial_check()

            self._stop_event.clear()
            self._checker_thread = threading.Thread(
                target=self._periodic_checker,
                name="guardian-checker",
                daemon=True,
            )
            self._checker_thread.start()
            self._started = True

        logger.info("guardian client started (module=%s)", self._module)

    def stop(self) -> None:
        """Stop the periodic checker thread and close the connection.

        Safe to call multiple times.  Blocks until the background thread
        has exited (with a reasonable timeout).
        """
        with self._lock:
            if not self._started:
                return
            self._started = False

        self._stop_event.set()

        if self._checker_thread is not None:
            self._checker_thread.join(timeout=10)
            self._checker_thread = None

        self._disconnect()
        logger.info("guardian client stopped")

    def force_check(self) -> LicenseDetails:
        """Perform an immediate license check.

        Returns:
            A populated :class:`LicenseDetails` instance.

        Raises:
            GuardianLicenseError: If the license is invalid and no
                *invalid_handler* absorbed the error.
            GuardianConnectionError: If the daemon is unreachable.
        """
        with self._lock:
            self._ensure_connected()
            return self._do_license_check()

    @property
    def is_connected(self) -> bool:
        """True if the client currently holds an authenticated connection."""
        with self._lock:
            return self._sock is not None and self._session_key is not None

    def status_check(self) -> StatusInfo:
        """Perform an anonymous status check using this client's socket path.

        Does not require :meth:`start` to have been called.  No token file
        or authentication is needed.

        Returns:
            A populated :class:`StatusInfo` instance.

        Raises:
            GuardianConnectionError: If the daemon is unreachable.
            GuardianProtocolError: On wire-protocol violations.
        """
        return check_status(self._socket_path)

    # ------------------------------------------------------------------
    # Connection management (must hold self._lock)
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """Establish connection and perform the mutual auth handshake."""
        self._disconnect_unlocked()

        # Parse credentials (once, then cache).
        if self._creds is None:
            self._creds = _parse_token_file(self._token_path)

        creds = self._creds

        # Open Unix socket.
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self._socket_path)
        except OSError as exc:
            raise GuardianConnectionError(
                f"cannot connect to {self._socket_path}: {exc}"
            ) from exc

        try:
            self._handshake(sock, creds)
        except Exception:
            sock.close()
            raise

    def _handshake(self, sock: socket.socket, creds: _TokenFileCredentials) -> None:
        """Perform the GUARDIAN_HELLO / SERVICE_AUTH / AUTH_RESULT handshake."""

        # Step 1: Read GUARDIAN_HELLO
        msg_type, payload = _read_message(sock)
        if msg_type != _MSG_GUARDIAN_HELLO:
            raise GuardianProtocolError(
                f"expected GUARDIAN_HELLO (0x{_MSG_GUARDIAN_HELLO:02x}), "
                f"got 0x{msg_type:02x}"
            )

        hello = msgpack.unpackb(payload, raw=False)
        guardian_nonce: bytes = hello["guardian_nonce"]
        signature: bytes = hello["signature"]

        # Ensure we have bytes, not str
        if isinstance(guardian_nonce, str):
            guardian_nonce = guardian_nonce.encode("latin-1")
        if isinstance(signature, str):
            signature = signature.encode("latin-1")

        # Step 2: Verify daemon signature
        if not _verify_ed25519(creds.daemon_pub, guardian_nonce, signature):
            raise GuardianAuthError(
                "invalid guardian signature -- possible fake guardian"
            )

        # Step 3: Generate client nonce and compute HMAC
        client_nonce = os.urandom(_CLIENT_NONCE_SIZE)
        hmac_value = _hmac_sha256(guardian_nonce + client_nonce, creds.token)

        svc_auth = {
            "service_id": creds.service_id,
            "client_nonce": client_nonce,
            "hmac": hmac_value,
        }
        _write_message(sock, _MSG_SERVICE_AUTH, svc_auth)

        # Step 4: Read AUTH_RESULT
        msg_type, payload = _read_message(sock)
        if msg_type != _MSG_AUTH_RESULT:
            raise GuardianProtocolError(
                f"expected AUTH_RESULT (0x{_MSG_AUTH_RESULT:02x}), "
                f"got 0x{msg_type:02x}"
            )

        result = msgpack.unpackb(payload, raw=False)
        status = result.get("status", "")
        if status != "ok":
            error_msg = result.get("error", "unknown authentication error")
            raise GuardianAuthError(f"authentication failed: {error_msg}")

        self._session_id = result.get("session_id", "")

        # Step 5: Derive session key
        session_key = _derive_session_key(guardian_nonce, client_nonce, creds.token)

        # Store state
        self._sock = sock
        self._session_key = session_key

        logger.info(
            "authenticated as %s (session=%s)",
            creds.service_id,
            self._session_id,
        )

    def _disconnect(self) -> None:
        """Close the connection (acquires the lock)."""
        with self._lock:
            self._disconnect_unlocked()

    def _disconnect_unlocked(self) -> None:
        """Close the connection (caller must hold the lock)."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._session_key = None
        self._session_id = ""

    def _ensure_connected(self) -> None:
        """Reconnect if the socket is not currently open (caller holds lock)."""
        if self._sock is None or self._session_key is None:
            self._connect()

    # ------------------------------------------------------------------
    # License and heartbeat operations (must hold self._lock)
    # ------------------------------------------------------------------

    def _do_license_check(self) -> LicenseDetails:
        """Send LICENSE_REQUEST, read LICENSE_RESPONSE, invoke callbacks.

        Returns:
            Populated :class:`LicenseDetails`.

        Raises:
            GuardianLicenseError: If the license is invalid and no
                *invalid_handler* is registered.
        """
        assert self._sock is not None and self._session_key is not None

        req = {"module": self._module}
        _write_encrypted_message(
            self._sock, _MSG_LICENSE_REQUEST, req, self._session_key
        )

        inner_type, resp = _read_encrypted_message(self._sock, self._session_key)
        if inner_type != _MSG_LICENSE_RESPONSE:
            raise GuardianProtocolError(
                f"expected LICENSE_RESPONSE (0x{_MSG_LICENSE_RESPONSE:02x}), "
                f"got 0x{inner_type:02x}"
            )

        details = LicenseDetails(
            valid=bool(resp.get("valid", False)),
            module=resp.get("module", ""),
            expires_at=resp.get("expires_at", ""),
            features=list(resp.get("features") or []),
            metadata=dict(resp.get("metadata") or {}),
        )

        error_str = resp.get("error", "")

        if details.valid:
            self._fire_valid(details)
        else:
            self._fire_invalid(details, error_str)

        return details

    def _do_heartbeat(self) -> LicenseDetails:
        """Send HEARTBEAT_PING, read HEARTBEAT_PONG, return updated details.

        The returned :class:`LicenseDetails` contains heartbeat-specific
        fields (hw_status, license_status, expires_in_days) but not
        license-check fields (valid, features, metadata).
        """
        assert self._sock is not None and self._session_key is not None

        ping = {"timestamp": int(time.time())}
        _write_encrypted_message(
            self._sock, _MSG_HEARTBEAT_PING, ping, self._session_key
        )

        inner_type, pong = _read_encrypted_message(self._sock, self._session_key)
        if inner_type != _MSG_HEARTBEAT_PONG:
            raise GuardianProtocolError(
                f"expected HEARTBEAT_PONG (0x{_MSG_HEARTBEAT_PONG:02x}), "
                f"got 0x{inner_type:02x}"
            )

        details = LicenseDetails(
            hw_status=pong.get("hw_status", ""),
            license_status=pong.get("license_status", ""),
            expires_in_days=int(pong.get("expires_in_days", 0)),
        )

        return details

    def _do_full_check(self) -> LicenseDetails:
        """Perform heartbeat + license check and merge results."""
        hb = self._do_heartbeat()
        lic = self._do_license_check()

        # Merge heartbeat data into the license details
        lic.hw_status = hb.hw_status
        lic.license_status = hb.license_status
        lic.expires_in_days = hb.expires_in_days

        return lic

    # ------------------------------------------------------------------
    # Initial check (called during start, holds the lock)
    # ------------------------------------------------------------------

    def _initial_check(self) -> None:
        """Run the first license check immediately after authentication."""
        try:
            self._do_full_check()
        except GuardianLicenseError:
            # The invalid_handler was already invoked inside _do_license_check.
            # If there is no handler, _fire_invalid will have raised, so we
            # only arrive here when there IS a handler -- nothing more to do.
            pass

    # ------------------------------------------------------------------
    # Callback helpers
    # ------------------------------------------------------------------

    def _fire_valid(self, details: LicenseDetails) -> None:
        if self._valid_handler is not None:
            try:
                self._valid_handler(details)
            except Exception:
                logger.exception("exception in valid_handler callback")

    def _fire_invalid(self, details: LicenseDetails, error: str) -> None:
        if self._invalid_handler is not None:
            try:
                self._invalid_handler(details, error)
            except Exception:
                logger.exception("exception in invalid_handler callback")
        else:
            raise GuardianLicenseError(
                f"license check failed for module {details.module!r}: {error}"
            )

    # ------------------------------------------------------------------
    # Background periodic checker
    # ------------------------------------------------------------------

    def _periodic_checker(self) -> None:
        """Background thread: periodically run heartbeat + license check.

        On connection loss, attempts to reconnect with exponential backoff
        before resuming the check cycle.
        """
        backoff = 1.0
        max_backoff = 60.0

        while not self._stop_event.is_set():
            # Wait for the check interval (or until stop is requested).
            if self._stop_event.wait(timeout=self._check_interval):
                break

            try:
                with self._lock:
                    self._ensure_connected()
                    self._do_full_check()
                # Reset backoff on success.
                backoff = 1.0
            except GuardianLicenseError:
                # Callback was fired; keep running.
                backoff = 1.0
            except (GuardianConnectionError, GuardianProtocolError, OSError) as exc:
                logger.warning(
                    "periodic check failed (will reconnect in %.0fs): %s",
                    backoff,
                    exc,
                )
                with self._lock:
                    self._disconnect_unlocked()

                # Exponential backoff before reconnect attempt.
                if self._stop_event.wait(timeout=backoff):
                    break
                backoff = min(backoff * 2, max_backoff)

                try:
                    with self._lock:
                        self._connect()
                    logger.info("reconnected successfully")
                    backoff = 1.0
                except (GuardianConnectionError, GuardianAuthError) as exc:
                    logger.warning("reconnect failed: %s", exc)
            except Exception:
                logger.exception("unexpected error in periodic checker")

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "GuardianClient":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<GuardianClient module={self._module!r} "
            f"socket={self._socket_path!r} "
            f"connected={self.is_connected}>"
        )
