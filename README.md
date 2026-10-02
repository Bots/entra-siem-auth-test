# Entra SIEM Authentication Flow Test

Two separate tools for authorized SIEM detection development:

- `login1.py` drives a real Microsoft Entra browser flow.
- `auth_test_server.py` is an optional local login fixture for testing collectors and dashboards. The Microsoft script does not authenticate against this server.

Use these tools only against accounts, systems, and Entra tenants you own or are explicitly authorized to test.

## 1. Install

Python 3.11 or newer is recommended.

    python -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/playwright install chromium

NordVPN must also be installed, logged in, and available as `nordvpn` on `PATH` before using the Microsoft harness.

## 2. Microsoft Entra harness

Run:

    .venv/bin/python login1.py

The script opens one Chromium browser and preserves the same browser process, context, page, cookie jar, and CDP session for the full sequence.

For each attempt it:

1. Connects NordVPN to the configured location.
2. Verifies the NordVPN city or country.
3. Verifies through Chromium that the public IP changed.
4. Changes and verifies the browser User-Agent.
5. Prompts for a username and hidden password.
6. Submits the real Microsoft login form.
7. Records only approved metadata in `entra_auth_test_results.csv`.

Expected sequence:

- Attempts 1–9: valid usernames with intentionally incorrect passwords.
- Attempts 7–9 use Canada, the United Kingdom, and Germany.
- Attempt 10: valid username and correct password from Dallas.

The script stops early if VPN/IP/User-Agent verification fails, browser automation fails, or an authentication outcome does not match the expected sequence. It does not mark a partial run complete.

### Password handling

Passwords are entered with `getpass`, filled into the Microsoft form, and then the local Python reference is discarded. They are never intentionally printed or written to CSV. Do not enable Playwright tracing, request-body logging, debug logging, or raw exception output around authentication.

The harness always prompts manually. It does not read Microsoft credentials from the server configuration or from a credential file.

### CSV fields

- UTC timestamp
- username
- attempt number
- User-Agent
- browser-observed public source IP
- NordVPN location
- authentication response status
- Microsoft result/error code when visible
- correlation ID when available
- request ID when available
- categorized result

Microsoft may issue a different request or correlation ID for every attempt; the script does not assume either remains constant.

## 3. Local authentication test server

The server is independent of the Microsoft harness. It provides a basic HTML login form, Argon2 password checking, a stable browser-session ID, a new request ID for every submitted login, JSONL event logging, and a limit of one authentication attempt per source IP per second.

For a quick local test, no environment variables are required:

    .venv/bin/python auth_test_server.py

It binds only to `127.0.0.1:8000`, generates an in-memory session secret, and uses:

- Username: `test@example.com`
- Password: `LocalTestOnly123!`

Set explicit credentials for anything beyond this loopback-only smoke test.

### Single test user

To replace the local defaults, set these variables in the shell:

    export TEST_USERNAME='test@example.invalid'
    export TEST_PASSWORD='replace-with-a-test-only-password'
    export SESSION_SECRET='replace-with-at-least-32-random-characters'

### Multiple test users

Set `TEST_USERNAME` to a JSON array instead of using the single-user pair. The array can contain nine username/password combinations or any other non-empty number. `TEST_USERS_JSON` is accepted as a clearer alias:

    export TEST_USERNAME='[
      {"username":"user1@example.invalid","password":"test-password-1"},
      {"username":"user2@example.invalid","password":"test-password-2"},
      {"username":"user3@example.invalid","password":"test-password-3"}
    ]'
    export SESSION_SECRET='replace-with-at-least-32-random-characters'

Each username must be unique. Empty usernames/passwords and malformed JSON are rejected. Passwords are converted to Argon2 hashes during startup, and the startup credential list is discarded. Passwords are excluded from server logs by an explicit field allowlist.

### Start the server

    .venv/bin/python auth_test_server.py

Then open:

    http://127.0.0.1:8000/

Health endpoint:

    http://127.0.0.1:8000/health

Events are appended to `auth_test_events.jsonl` unless `AUTH_LOG_FILE` is set.

### Server settings

- `AUTH_HOST`: bind address; defaults to `127.0.0.1`.
- `AUTH_PORT`: port; defaults to `8000`.
- `AUTH_LOG_FILE`: JSONL output path.
- `SESSION_HTTPS_ONLY`: must be `true` for a non-loopback bind.
- `TRUST_PROXY_HEADERS`: use `X-Forwarded-For` only behind a trusted reverse proxy that blocks direct client access.

For loopback use, a missing session secret is generated in memory at startup. A supplied secret must contain at least 32 characters and cannot be the `.env.example` placeholder. Non-loopback binds require an explicit session secret and HTTPS-only cookies.

## 4. Checks

These checks do not launch the browser, server, or VPN workflow:

    .venv/bin/python -m unittest discover -s tests -v
    .venv/bin/python -m py_compile auth_test_core.py auth_test_server.py login1.py

GitHub Actions runs the same checks for pushes to `main` and pull requests.
