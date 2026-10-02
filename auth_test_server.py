#!/usr/bin/env python3

"""
SIEM Authentication Test Server
===============================

Purpose
-------
This FastAPI application provides a deliberately simple authentication target
for authorized SIEM and detection-engineering testing.

It is intended to be used with a browser automation harness that changes:

    - source IP
    - VPN location
    - User-Agent
    - username
    - authentication outcome

while preserving the same browser session.

The server records only non-sensitive authentication metadata.

IT NEVER LOGS PASSWORDS.

Logged fields
-------------
    timestamp
    username
    source_ip
    user_agent
    session_id
    request_id
    http_status
    result

Session behavior
----------------
A browser receives a random session cookie named:

    siem_test_session

That cookie remains constant across authentication attempts as long as the
browser preserves its cookies.

Every login attempt receives a NEW request_id.

This gives SIEM tooling two useful correlation dimensions:

    session_id  -> browser/session continuity
    request_id  -> individual authentication event

Password handling
-----------------
Passwords are:

    - accepted by the POST /login endpoint
    - checked against Argon2 hashes
    - never printed
    - never written to disk
    - never included in structured logging
    - never returned to the client

The password variable is discarded as soon as authentication completes.

Reverse proxy behavior
----------------------
By default, the server trusts request.client.host.

If this application is behind a reverse proxy such as:

    Nginx
    Cloudflare
    Traefik
    Caddy

set:

    TRUST_PROXY_HEADERS=true

Then the application will use X-Forwarded-For.

ONLY enable this if your application is reachable exclusively through a
trusted reverse proxy.

Otherwise a client could spoof X-Forwarded-For.
"""

import json
import os
import threading
import time
import uuid
from collections import OrderedDict

from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware


# ============================================================================
# CONFIGURATION
# ============================================================================

APP_TITLE = "SIEM Authentication Test Server"

LOG_FILE = Path(
    os.getenv(
        "AUTH_LOG_FILE",
        "auth_test_events.jsonl",
    )
)

# Enable this ONLY when running behind a trusted reverse proxy.
TRUST_PROXY_HEADERS = (
    os.getenv(
        "TRUST_PROXY_HEADERS",
        "false",
    ).lower()
    == "true"
)


def load_server_config(environ):
    """Load required credentials with loopback-safe defaults."""

    def required(name):
        value = environ.get(name, "").strip()
        if not value:
            raise ValueError(f"{name} must be set")
        return value

    session_secret = required("SESSION_SECRET")

    username_value = environ.get("TEST_USERNAME", "").strip()
    raw_users = environ.get("TEST_USERS_JSON", "").strip()
    if not raw_users and username_value.startswith("["):
        raw_users = username_value
    if raw_users:
        try:
            entries = json.loads(raw_users)
            if not isinstance(entries, list):
                raise TypeError
            credentials = []
            for entry in entries:
                username = entry["username"]
                password = entry["password"]
                if not isinstance(username, str) or not isinstance(password, str):
                    raise TypeError
                credentials.append((username.strip(), password))
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError(
                "TEST_USERS_JSON must be a JSON array of username/password objects"
            ) from error

        if not credentials or any(not username or not password for username, password in credentials):
            raise ValueError("TEST_USERS_JSON contains an empty username or password")
        if len({username.lower() for username, _ in credentials}) != len(credentials):
            raise ValueError("TEST_USERS_JSON contains duplicate usernames")
    else:
        credentials = [(required("TEST_USERNAME"), required("TEST_PASSWORD"))]

    if len(session_secret) < 32:
        raise ValueError("SESSION_SECRET must contain at least 32 characters")
    if session_secret.lower().startswith("replace-"):
        raise ValueError("SESSION_SECRET must not use the example placeholder")

    host = environ.get("AUTH_HOST", "127.0.0.1").strip()
    https_only = environ.get("SESSION_HTTPS_ONLY", "false").lower() == "true"
    if host not in {"127.0.0.1", "localhost", "::1"} and not https_only:
        raise ValueError(
            "SESSION_HTTPS_ONLY=true is required when AUTH_HOST is not loopback"
        )

    config = {
        "session_secret": session_secret,
        "host": host,
        "port": int(environ.get("AUTH_PORT", "8000")),
        "https_only": https_only,
    }
    return config, credentials


CONFIG, startup_credentials = load_server_config(os.environ)
SESSION_SECRET = CONFIG["session_secret"]


# ============================================================================
# PASSWORD HASHING
# ============================================================================

# Argon2 is used so plaintext passwords do not need to be stored.
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
)


# ============================================================================
# TEST ACCOUNTS
# ============================================================================

"""
Configure either one test account or a JSON array of accounts.

Set these before starting the server:

    export TEST_USERNAME='test@example.com'
    export TEST_PASSWORD='CorrectHorseBatteryStaple'
    export SESSION_SECRET='replace-with-a-long-random-value'

For multiple accounts, set TEST_USERS_JSON instead of TEST_USERNAME and
TEST_PASSWORD. See README.md for the JSON format.

The plaintext password exists only in process memory while the application
starts.

The application immediately converts it to an Argon2 hash.

The password itself is NEVER logged.

"""

# Hash immediately at startup.
TEST_USERS = {
    username.lower(): pwd_context.hash(password)
    for username, password in startup_credentials
}


# Drop the module-level plaintext reference.
startup_credentials = None
os.environ.pop("TEST_USERNAME", None)
os.environ.pop("TEST_PASSWORD", None)
os.environ.pop("TEST_USERS_JSON", None)


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title=APP_TITLE,
    docs_url=None,
    redoc_url=None,
)


# SessionMiddleware provides a signed browser session cookie.
#
# The cookie gives us a stable session identifier across authentication
# attempts without storing passwords or authentication payloads.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="siem_test_session",
    same_site="lax",
    https_only=CONFIG["https_only"],
)


# ============================================================================
# HTML
# ============================================================================

LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>SIEM Authentication Test</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;

            display: flex;
            align-items: center;
            justify-content: center;

            font-family:
                Inter,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;

            background:
                linear-gradient(
                    135deg,
                    #111827,
                    #020617
                );

            color: #e5e7eb;
        }

        .card {
            width: 420px;
            max-width: calc(100vw - 32px);

            padding: 36px;

            border: 1px solid #273449;
            border-radius: 16px;

            background: rgba(
                15,
                23,
                42,
                0.96
            );

            box-shadow:
                0 20px 60px rgba(
                    0,
                    0,
                    0,
                    0.35
                );
        }

        h1 {
            margin: 0 0 8px 0;
            font-size: 24px;
        }

        .subtitle {
            margin-bottom: 30px;
            color: #94a3b8;
            font-size: 14px;
        }

        label {
            display: block;

            margin-bottom: 8px;

            font-size: 13px;
            font-weight: 600;

            color: #cbd5e1;
        }

        input {
            width: 100%;

            margin-bottom: 20px;
            padding: 13px 14px;

            border: 1px solid #334155;
            border-radius: 8px;

            background: #020617;
            color: white;

            font-size: 15px;

            outline: none;
        }

        input:focus {
            border-color: #60a5fa;
        }

        button {
            width: 100%;

            padding: 13px;

            border: none;
            border-radius: 8px;

            background: #2563eb;
            color: white;

            font-size: 15px;
            font-weight: 600;

            cursor: pointer;
        }

        button:hover {
            background: #1d4ed8;
        }

        .notice {
            margin-top: 22px;

            color: #64748b;
            font-size: 12px;
            line-height: 1.5;
        }
    </style>
</head>

<body>

<div class="card">

    <h1>Authentication Test</h1>

    <div class="subtitle">
        Authorized SIEM detection-engineering environment
    </div>

    <form method="POST" action="/login">

        <label for="username">
            Username
        </label>

        <input
            id="username"
            name="username"
            type="email"
            autocomplete="username"
            required
            autofocus
        >

        <label for="password">
            Password
        </label>

        <input
            id="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
        >

        <button
            id="login-button"
            type="submit"
        >
            Sign in
        </button>

    </form>

    <div class="notice">
        Authentication telemetry from this environment is generated
        specifically for security monitoring and detection testing.
    </div>

</div>

</body>
</html>
"""


SUCCESS_PAGE = """
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">

    <title>Authentication Successful</title>

    <style>
        body {
            margin: 0;

            min-height: 100vh;

            display: grid;
            place-items: center;

            background: #020617;
            color: #e5e7eb;

            font-family:
                Inter,
                system-ui,
                sans-serif;
        }

        .box {
            padding: 40px;

            border: 1px solid #14532d;
            border-radius: 16px;

            background: #052e16;

            text-align: center;
        }

        h1 {
            color: #4ade80;
        }
    </style>
</head>

<body>

<div class="box">

    <h1>Authentication successful</h1>

    <p>
        The authentication event was recorded.
    </p>

</div>

</body>
</html>
"""


FAILED_PAGE = """
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">

    <title>Authentication Failed</title>

    <style>
        body {
            margin: 0;

            min-height: 100vh;

            display: grid;
            place-items: center;

            background: #020617;
            color: #e5e7eb;

            font-family:
                Inter,
                system-ui,
                sans-serif;
        }

        .box {
            padding: 40px;

            border: 1px solid #7f1d1d;
            border-radius: 16px;

            background: #450a0a;

            text-align: center;
        }

        h1 {
            color: #f87171;
        }

        a {
            color: #93c5fd;
        }
    </style>
</head>

<body>

<div class="box">

    <h1>Authentication failed</h1>

    <p>
        Invalid username or password.
    </p>

    <p>
        <a href="/">
            Try again
        </a>
    </p>

</div>

</body>
</html>
"""


# ============================================================================
# HELPERS
# ============================================================================

class AttemptRateLimiter:
    """Allow at most one authentication attempt per key and interval."""

    def __init__(self, minimum_interval_seconds=1.0, max_keys=10000):
        self.minimum_interval_seconds = minimum_interval_seconds
        self.max_keys = max_keys
        self._last_attempt = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key, now=None):
        """Record an allowed attempt, or reject one that arrives too soon."""

        current_time = time.monotonic() if now is None else now

        with self._lock:
            while self._last_attempt:
                _, oldest_time = next(iter(self._last_attempt.items()))

                if current_time - oldest_time < self.minimum_interval_seconds:
                    break

                self._last_attempt.popitem(last=False)

            previous_time = self._last_attempt.get(key)

            if (
                previous_time is not None
                and current_time - previous_time < self.minimum_interval_seconds
            ):
                return False

            self._last_attempt.pop(key, None)
            self._last_attempt[key] = current_time

            while len(self._last_attempt) > self.max_keys:
                self._last_attempt.popitem(last=False)

            return True


attempt_rate_limiter = AttemptRateLimiter(
    minimum_interval_seconds=1.0,
)

def utc_timestamp():
    """
    Return an ISO-8601 UTC timestamp suitable for SIEM ingestion.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


def get_source_ip(request: Request):
    """
    Determine the source address to record.

    Direct server:
        request.client.host

    Trusted reverse proxy:
        first address in X-Forwarded-For

    WARNING:
        X-Forwarded-For is client-controlled unless overwritten by a trusted
        reverse proxy.

        Never enable TRUST_PROXY_HEADERS on an Internet-facing server unless
        clients cannot connect directly to this application.
    """

    if TRUST_PROXY_HEADERS:

        forwarded = request.headers.get(
            "x-forwarded-for"
        )

        if forwarded:

            # Standard X-Forwarded-For format:
            #
            # client, proxy1, proxy2
            #
            # The first entry is normally the original client.
            return (
                forwarded
                .split(",")[0]
                .strip()
            )

    if request.client:
        return request.client.host

    return "unknown"


def get_or_create_session_id(request: Request):
    """
    Return a stable random identifier for this browser session.

    This is deliberately separate from request_id.

    Example:

        session_id = same across attempts
        request_id = different for every login attempt

    This makes detection/correlation behavior easy to validate.
    """

    session_id = request.session.get(
        "test_session_id"
    )

    if not session_id:

        session_id = str(
            uuid.uuid4()
        )

        request.session[
            "test_session_id"
        ] = session_id

    return session_id


def log_auth_event(event):
    """
    Append a single authentication event as JSON Lines.

    SECURITY DESIGN:
        We construct the stored object from an explicit allow-list.

        There is no password field.

        The function will therefore ignore unexpected values even if someone
        accidentally passes them in.
    """

    allowed_fields = [
        "timestamp",
        "username",
        "source_ip",
        "user_agent",
        "session_id",
        "request_id",
        "http_status",
        "result",
    ]

    safe_event = {
        field: event.get(
            field,
            ""
        )
        for field in allowed_fields
    }

    with LOG_FILE.open(
        "a",
        encoding="utf-8",
    ) as handle:

        handle.write(
            json.dumps(
                safe_event,
                separators=(",", ":"),
            )
        )

        handle.write("\n")


def authenticate(username, password):
    """
    Verify username/password against the configured test accounts.

    The function returns only True/False.

    Password contents are never logged or returned.
    """

    username_key = username.lower()

    password_hash = TEST_USERS.get(
        username_key
    )

    if not password_hash:
        return False

    try:
        return pwd_context.verify(
            password,
            password_hash,
        )

    except Exception:
        return False


# ============================================================================
# ROUTES
# ============================================================================

@app.get(
    "/",
    response_class=HTMLResponse,
)
async def login_page(request: Request):
    """
    Display the login page.

    Merely viewing the login page does not create an authentication event,
    although it does establish the browser session identifier.
    """

    get_or_create_session_id(
        request
    )

    return HTMLResponse(
        LOGIN_PAGE,
        status_code=200,
    )


@app.post(
    "/login",
)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """
    Process a login attempt.

    A unique request_id is generated for every attempt.

    The existing session_id is retained across attempts.

    Password handling sequence:

        1. FastAPI parses form field.
        2. authenticate() verifies it against an Argon2 hash.
        3. Result becomes True/False.
        4. Local password reference is discarded.
        5. Only approved metadata is logged.
    """

    timestamp = utc_timestamp()

    request_id = str(
        uuid.uuid4()
    )

    session_id = get_or_create_session_id(
        request
    )

    source_ip = get_source_ip(
        request
    )

    user_agent = request.headers.get(
        "user-agent",
        "unknown",
    )

    if not attempt_rate_limiter.allow(source_ip):
        return HTMLResponse(
            "Too many authentication attempts. Retry in one second.",
            status_code=429,
            headers={"Retry-After": "1"},
        )


    # ------------------------------------------------------------
    # AUTHENTICATION
    # ------------------------------------------------------------

    authenticated = authenticate(
        username,
        password,
    )


    # Remove our application reference immediately after verification.
    #
    # This is not guaranteed secure memory zeroization because Python strings
    # are immutable, but it prevents unnecessary application-level retention.
    password = None


    # ------------------------------------------------------------
    # SUCCESS
    # ------------------------------------------------------------

    if authenticated:

        log_auth_event(
            {
                "timestamp": timestamp,
                "username": username,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "session_id": session_id,
                "request_id": request_id,
                "http_status": 303,
                "result": "success",
            }
        )

        return RedirectResponse(
            url="/login-success",
            status_code=303,
        )


    # ------------------------------------------------------------
    # FAILURE
    # ------------------------------------------------------------

    log_auth_event(
        {
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "session_id": session_id,
            "request_id": request_id,
            "http_status": 303,
            "result": "failure",
        }
    )

    return RedirectResponse(
        url="/login-failed",
        status_code=303,
    )


@app.get(
    "/login-success",
    response_class=HTMLResponse,
)
async def login_success():
    """
    Stable URL used by the Playwright test harness to recognize successful
    authentication.
    """

    return HTMLResponse(
        SUCCESS_PAGE,
        status_code=200,
    )


@app.get(
    "/login-failed",
    response_class=HTMLResponse,
)
async def login_failed():
    """
    Stable URL used by the Playwright test harness to recognize failed
    authentication.
    """

    return HTMLResponse(
        FAILED_PAGE,
        status_code=401,
    )


@app.get(
    "/health",
)
async def health():
    """
    Simple health endpoint for Docker, reverse proxies, or uptime checks.
    """

    return {
        "status": "ok",
        "service": APP_TITLE,
    }


# ============================================================================
# LOCAL DEVELOPMENT ENTRY POINT
# ============================================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "auth_test_server:app",

        # Loopback is the safe default. A remote bind requires an HTTPS-only
        # session cookie and an explicit AUTH_HOST setting.
        host=CONFIG["host"],

        port=CONFIG["port"],

        # Disable reload for the actual test so restarting the application
        # does not invalidate session state halfway through the sequence.
        reload=False,

        # Normal Uvicorn access logging does not contain form request bodies,
        # but disabling it keeps our test telemetry narrowly controlled.
        access_log=False,
    )