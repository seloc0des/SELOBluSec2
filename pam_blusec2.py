"""
BluSec 2.0 - PAM Authentication Module

Designed to be invoked by pam_exec.so.  Authenticates users by requiring
both BLE proximity verification (challenge-response) and password
validation (Argon2).

PAM configuration example (/etc/pam.d/sudo or similar):

    auth  required  pam_exec.so  expose_authtok  /usr/local/bin/blusec2-pam

Environment variables set by pam_exec.so:

    PAM_USER  - The username being authenticated
    PAM_TYPE  - The PAM management group (auth, account, session, password)
    PAM_RHOST - Remote host (if applicable)

Additional environment variables (optional overrides):

    BLUSEC2_CONFIG_DIR - Config directory (default: /etc/blusec2)
    BLUSEC2_TIMEOUT    - Auth timeout in seconds (default: 30)

Exit codes:

    0 - PAM_SUCCESS  (authentication passed)
    1 - PAM_AUTH_ERR (authentication failed)
"""

import asyncio
import logging
import logging.handlers
import os
import sys
import select
from typing import Optional

from blusec2_auth import BluSec2Authenticator

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
CONFIG_DIR = os.environ.get("BLUSEC2_CONFIG_DIR", "/etc/blusec2")
AUTH_TIMEOUT = int(os.environ.get("BLUSEC2_TIMEOUT", "30"))


# ---------------------------------------------------------------------------
# Logging — all output goes to syslog so PAM stays clean
# ---------------------------------------------------------------------------
def _setup_logging() -> logging.Logger:
    """Configure syslog logging for PAM context."""
    logger = logging.getLogger("pam_blusec2")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on re-import
    if not logger.handlers:
        try:
            handler = logging.handlers.SysLogHandler(address="/dev/log")
        except Exception:
            # Fallback if /dev/log is unavailable (e.g. containers)
            handler = logging.handlers.SysLogHandler()
        handler.setFormatter(
            logging.Formatter("pam_blusec2[%(process)d]: %(message)s")
        )
        logger.addHandler(handler)

    return logger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_password(timeout: float = 2.0) -> Optional[str]:
    """Read password from stdin (passed by pam_exec expose_authtok).

    pam_exec writes the password as a single line on stdin when the
    ``expose_authtok`` option is set. If expose_authtok is NOT set
    (e.g., PAM Option C for MFA), stdin will have no data and this
    function returns None after the timeout.

    Args:
        timeout: Seconds to wait for stdin data (default: 2.0).
                 Increased from 0.5s to accommodate slow systems and I/O contention.

    Returns:
        Password string if available, None otherwise.
    """
    try:
        # Check if stdin has data available within timeout
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if not ready:
            # No data on stdin - expose_authtok not set
            return None

        # pam_exec sends a NUL-terminated token followed by a newline
        password = sys.stdin.readline().rstrip("\n\x00")
        return password if password else None
    except Exception:
        return None


def _suppress_stdout():
    """Redirect stdout/stderr to /dev/null in PAM context.

    The BluSec2Authenticator prints user-facing messages via print().
    In PAM context those would leak to the user's terminal on some
    configurations, so we silence them.  Logging still goes to syslog.

    Opens /dev/null with a file descriptor that persists for the
    process lifetime (intentional in PAM context — the process exits
    shortly after authentication completes).
    """
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull_fd, sys.stdout.fileno())
    os.dup2(devnull_fd, sys.stderr.fileno())
    os.close(devnull_fd)


# ---------------------------------------------------------------------------
# Core authentication
# ---------------------------------------------------------------------------
async def _authenticate(
    username: str,
    password: Optional[str],
    logger: logging.Logger,
) -> bool:
    """Run the full BluSec2 authentication flow.

    When *password* is None the authenticator runs in proximity-only mode
    (useful for PAM MFA where pam_unix already verified the password).
    """
    auth = None
    try:
        auth = BluSec2Authenticator(config_dir=CONFIG_DIR, user=username)
    except FileNotFoundError as exc:
        logger.error("Config error for user %s: %s", username, exc)
        return False
    except Exception as exc:
        logger.error("Init error: %s", exc)
        return False

    proximity_only = password is None
    try:
        # Note: authenticate() handles its own timeout internally.
        # We don't wrap it in another wait_for to avoid double timeout
        # overhead (which would reduce effective auth time).
        result = await auth.authenticate(
            password=password,
            prompt=False,
            proximity_only=proximity_only,
            timeout=AUTH_TIMEOUT,
        )
        return result
    except asyncio.TimeoutError:
        logger.warning("Timed out waiting for device (user %s)", username)
        return False
    except Exception as exc:
        logger.error("Auth error for user %s: %s", username, exc)
        return False
    finally:
        if auth is not None:
            await auth.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    """PAM exec entry point.  Returns 0 on success, 1 on failure."""
    logger = _setup_logging()

    # Only handle the 'auth' PAM type
    pam_type = os.environ.get("PAM_TYPE", "")
    if pam_type != "auth":
        # For non-auth types (account, session, password) pass through
        logger.debug("Ignoring PAM type: %s", pam_type)
        return 0

    username = os.environ.get("PAM_USER")
    if not username:
        logger.error("PAM_USER not set")
        return 1

    # Read password from stdin (set by pam_exec expose_authtok).
    # When expose_authtok is omitted (e.g. PAM MFA Option C) password
    # will be None and the authenticator runs in proximity-only mode.
    password = _read_password()

    # Suppress print() noise from the authenticator
    _suppress_stdout()

    mode = "proximity-only" if password is None else "full"
    logger.info("Auth attempt for user %s (mode: %s)", username, mode)

    success = asyncio.run(_authenticate(username, password, logger))

    if success:
        logger.info("Auth success for user %s", username)
        return 0

    logger.warning("Auth failed for user %s", username)
    return 1


def pam_main():
    """Console-scripts entry point for ``blusec2-pam``."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
