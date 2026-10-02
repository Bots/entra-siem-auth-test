#!/usr/bin/env python3

import csv
import getpass
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from auth_test_core import (
    MICROSOFT_START_URL,
    PASSWORD_SELECTOR,
    SUBMIT_SELECTOR,
    USERNAME_SELECTOR,
    classify_outcome,
    is_authentication_response,
    parse_nordvpn_status,
    public_ip_changed,
    vpn_location_matches,
)


LOG_FILE = Path("entra_auth_test_results.csv")
LOG_FIELDS = (
    "timestamp",
    "username",
    "attempt",
    "user_agent",
    "public_source_ip",
    "nordvpn_location",
    "http_result_status",
    "microsoft_result_code",
    "correlation_id",
    "request_id",
    "result",
)

# Attempts 1-9 are intentionally failed.
# Three attempts use different countries.
# Attempt 10 uses Dallas for the successful authentication.
VPN_LOCATIONS = [
    "New_York",
    "Los_Angeles",
    "Seattle",
    "Chicago",
    "Denver",
    "Miami",
    "Canada",
    "United_Kingdom",
    "Germany",
    "Dallas",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",

    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) "
    "Gecko/20100101 Firefox/141.0",

    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) "
    "Gecko/20100101 Firefox/140.0",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",

    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:139.0) "
    "Gecko/20100101 Firefox/139.0",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",

    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
]


AADSTS_RE = re.compile(r"\b(AADSTS\d+)\b", re.IGNORECASE)

CORRELATION_PATTERNS = [
    re.compile(
        r"Correlation\s*(?:ID|Id)\s*[:=]\s*"
        r"([0-9a-fA-F-]{20,})",
        re.IGNORECASE,
    ),
    re.compile(
        r"correlationId[\"']?\s*[:=]\s*[\"']"
        r"([0-9a-fA-F-]{20,})",
        re.IGNORECASE,
    ),
]

REQUEST_PATTERNS = [
    re.compile(
        r"Request\s*(?:ID|Id)\s*[:=]\s*"
        r"([0-9a-fA-F-]{20,})",
        re.IGNORECASE,
    ),
    re.compile(
        r"requestId[\"']?\s*[:=]\s*[\"']"
        r"([0-9a-fA-F-]{20,})",
        re.IGNORECASE,
    ),
]


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def run_nordvpn(*args, timeout=90):
    """Run NordVPN without exposing command output."""

    try:
        result = subprocess.run(
            ["nordvpn", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def rotate_vpn(page, location, previous_ip):
    """Connect and verify both the requested location and a new public IP."""

    print(f"\nConnecting NordVPN to: {location}")

    if run_nordvpn("c", location) is None:
        raise RuntimeError("NordVPN connection command failed")

    for check_number in range(5):
        status_output = run_nordvpn("status", timeout=10)

        if status_output is not None:
            actual_location = parse_nordvpn_status(status_output)

            if vpn_location_matches(location, actual_location):
                current_ip = get_browser_public_ip(page)

                if public_ip_changed(previous_ip, current_ip):
                    return current_ip

        if check_number < 4:
            time.sleep(2)

    raise RuntimeError("NordVPN location or public IP could not be verified")


def get_browser_public_ip(page):
    """Fetch the public IP through the preserved browser context."""

    try:
        page.goto(
            "https://api.ipify.org?format=json",
            wait_until="domcontentloaded",
            timeout=15000,
        )
        data = json.loads(page.locator("body").inner_text(timeout=3000))
        return data.get("ip", "unknown")
    except Exception:
        return "unknown"


def initialize_log():
    if LOG_FILE.exists():
        return

    with LOG_FILE.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=LOG_FIELDS,
        )
        writer.writeheader()


def write_log(record):
    """
    Only explicitly approved non-sensitive fields can reach disk.
    Passwords are never accepted by this function.
    """
    record = {key: record.get(key, "") for key in LOG_FIELDS}

    with LOG_FILE.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=LOG_FIELDS,
        )
        writer.writerow(record)


def first_match(text, patterns):
    if not text:
        return None

    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(1)

    return None


def safe_body_text(page):
    """
    Read visible text for Microsoft error/result identifiers.

    The returned text is NEVER logged wholesale.
    """
    try:
        return page.locator("body").inner_text(timeout=3000)
    except Exception:
        return ""


def click_if_visible(locator, timeout=1500):
    try:
        if locator.is_visible(timeout=timeout):
            locator.click(timeout=timeout)
            return True
    except Exception:
        pass

    return False


def prepare_username_page(page):
    """
    Get Microsoft back to an account/username selection state while
    preserving the existing browser context, cookies and storage.
    """
    page.goto(
        MICROSOFT_START_URL,
        wait_until="domcontentloaded",
        timeout=60000,
    )

    # Microsoft may show the account picker when session state exists.
    account_options = [
        page.get_by_text("Use another account", exact=False),
        page.get_by_text("Sign in with another account", exact=False),
        page.get_by_text("Use a different account", exact=False),
    ]

    for option in account_options:
        if click_if_visible(option):
            break

    # If Microsoft remembered a username and is already asking for its
    # password, try the standard Back control to change account.
    email_box = page.locator(USERNAME_SELECTOR)

    try:
        if not email_box.is_visible(timeout=2000):
            back = page.locator("#idBtn_Back")
            click_if_visible(back, timeout=1500)
    except Exception:
        pass

    # Account picker may appear after backing out.
    for option in account_options:
        if click_if_visible(option):
            break


def enter_username(page, username):
    email = page.locator(USERNAME_SELECTOR)
    email.wait_for(state="visible", timeout=20000)

    email.fill(username)

    submit = page.locator(SUBMIT_SELECTOR)
    submit.click(timeout=10000)

    password = page.locator(PASSWORD_SELECTOR)
    password.wait_for(state="visible", timeout=20000)


def enter_password(page, password):
    password_box = page.locator(PASSWORD_SELECTOR)

    # Password exists only in memory long enough to fill the browser form.
    password_box.fill(password)

    submit = page.locator(SUBMIT_SELECTOR)

    with page.expect_response(
        lambda response: is_authentication_response(
            response.request.method,
            response.url,
            response.request.is_navigation_request(),
        ),
        timeout=20000,
    ) as response_info:
        submit.click(timeout=10000)

    return response_info.value


def collect_page_identifiers(page):
    body = safe_body_text(page)

    result_code = None
    correlation_id = None
    request_id = None

    aadsts = AADSTS_RE.search(body)
    if aadsts:
        result_code = aadsts.group(1).upper()

    correlation_id = first_match(body, CORRELATION_PATTERNS)
    request_id = first_match(body, REQUEST_PATTERNS)

    return result_code, correlation_id, request_id


def update_from_headers(metadata, headers):
    """
    Capture only request/correlation identifiers from response headers.

    Response bodies and request bodies are intentionally ignored.
    """
    lower = {str(k).lower(): str(v) for k, v in headers.items()}

    if not metadata["request_id"]:
        for name in (
            "request-id",
            "x-ms-request-id",
            "x-msedge-ref",
        ):
            if lower.get(name):
                metadata["request_id"] = lower[name]
                break

    if not metadata["correlation_id"]:
        for name in (
            "correlation-id",
            "x-ms-correlation-id",
            "client-request-id",
        ):
            if lower.get(name):
                metadata["correlation_id"] = lower[name]
                break


def wait_for_auth_result(page):
    deadline = time.time() + 20

    result = "unknown"

    while time.time() < deadline:
        result = classify_outcome(page.url, safe_body_text(page))

        if result != "unknown":
            return result

        time.sleep(0.5)

    return result


def main():
    initialize_log()

    print("Microsoft Entra ID SIEM authentication-flow test")
    print("Passwords are entered invisibly and are never logged.")
    print()
    print("Attempts 1-9 should use intentionally incorrect passwords.")
    print("Attempt 10 should use the correct password.")
    print()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
            ],
        )

        # ONE browser context for the entire test.
        context = browser.new_context()

        # ONE page for the entire test.
        page = context.new_page()

        # ONE CDP session attached to that page.
        cdp = context.new_cdp_session(page)

        try:
            previous_public_ip = get_browser_public_ip(page)

            if previous_public_ip == "unknown":
                print("Unable to establish the initial public source IP.")
                return 1

            completed_attempts = 0
            last_result = None

            for index in range(10):
                attempt = index + 1
                location = VPN_LOCATIONS[index]
                user_agent = USER_AGENTS[index]

                print("\n" + "=" * 72)
                print(f"Attempt {attempt}/10")
                print(f"VPN location: {location}")
                print("=" * 72)


                # Rotate the public IP while leaving the browser process,
                # browser context, cookies and storage intact.
                try:
                    public_ip = rotate_vpn(
                        page,
                        location,
                        previous_public_ip,
                    )
                    previous_public_ip = public_ip
                except Exception:
                    print(
                        "VPN connection failed. Authentication attempt "
                        "was not performed."
                    )
                    write_log(
                        {
                            "timestamp": utc_timestamp(),
                            "username": "",
                            "attempt": attempt,
                            "user_agent": user_agent,
                            "public_source_ip": "unknown",
                            "nordvpn_location": location,
                            "http_result_status": "",
                            "microsoft_result_code": "",
                            "correlation_id": "",
                            "request_id": "",
                            "result": "vpn_connection_failed",
                        }
                    )
                    break

                print(f"Public source IP: {public_ip}")

                # Override the UA on the existing Chromium target instead
                # of constructing a new browser context.
                cdp.send(
                    "Network.setUserAgentOverride",
                    {
                        "userAgent": user_agent,
                        "platform": (
                            "Win32"
                            if "Windows" in user_agent
                            else "MacIntel"
                            if "Macintosh" in user_agent
                            else "Linux x86_64"
                        ),
                    },
                )

                if page.evaluate("navigator.userAgent") != user_agent:
                    print("User-Agent verification failed; stopping test.")
                    break

                username = input(
                    f"Username for attempt {attempt}: "
                ).strip()

                # getpass prevents terminal echo.
                password = getpass.getpass(
                    f"Password for attempt {attempt}: "
                )

                result = "unknown"
                microsoft_code = None
                page_correlation_id = None
                page_request_id = None
                current_metadata = {
                    "http_status": None,
                    "request_id": None,
                    "correlation_id": None,
                }

                try:
                    prepare_username_page(page)
                    enter_username(page, username)
                    auth_response = enter_password(page, password)

                    current_metadata["http_status"] = auth_response.status
                    update_from_headers(
                        current_metadata,
                        auth_response.headers,
                    )

                    submitted_user_agent = auth_response.request.headers.get(
                        "user-agent",
                        "",
                    )

                    if submitted_user_agent != user_agent:
                        result = "user_agent_mismatch"
                    else:
                        result = wait_for_auth_result(page)

                    # Remove the Python reference immediately after use.
                    password = None

                    (
                        microsoft_code,
                        page_correlation_id,
                        page_request_id,
                    ) = collect_page_identifiers(page)

                except PlaywrightTimeoutError:
                    # Do not print Playwright exception messages because
                    # browser automation errors may contain page details.
                    result = "timeout"

                except Exception:
                    # Never serialize exception messages or traceback data.
                    result = "browser_error"

                finally:
                    # Best-effort overwrite/removal of the Python reference.
                    password = None

                correlation_id = (
                    page_correlation_id
                    or current_metadata["correlation_id"]
                    or ""
                )

                request_id = (
                    page_request_id
                    or current_metadata["request_id"]
                    or ""
                )

                http_status = (
                    current_metadata["http_status"]
                    if current_metadata["http_status"] is not None
                    else ""
                )

                write_log(
                    {
                        "timestamp": utc_timestamp(),
                        "username": username,
                        "attempt": attempt,
                        "user_agent": user_agent,
                        "public_source_ip": public_ip,
                        "nordvpn_location": location,
                        "http_result_status": http_status,
                        "microsoft_result_code": microsoft_code or "",
                        "correlation_id": correlation_id,
                        "request_id": request_id,
                        "result": result,
                    }
                )

                print(f"Result: {result}")
                completed_attempts = attempt
                last_result = result

                if microsoft_code:
                    print(f"Microsoft result code: {microsoft_code}")

                if correlation_id:
                    print(f"Correlation ID: {correlation_id}")

                if request_id:
                    print(f"Request ID: {request_id}")

                expected_result = "failed" if attempt < 10 else "succeeded"

                if result != expected_result:
                    print(
                        f"Expected {expected_result}; stopping before the "
                        "sequence can be marked complete."
                    )
                    break

                if attempt < 10:
                    input(
                        "Press Enter when ready for the next attempt..."
                    )

            if completed_attempts == 10 and last_result == "succeeded":
                print(f"\nTest complete. Metadata saved to {LOG_FILE}")
                return 0

            print(f"\nTest stopped early. Partial metadata saved to {LOG_FILE}")
            return 1

        finally:
            try:
                context.close()
            except Exception:
                pass

            try:
                browser.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
