#!/usr/bin/env python3

import csv
import getpass
import json
import re
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from auth_test_core import (
    build_target,
    classify_outcome,
    is_authentication_response,
)


LOG_FILE = Path("entra_auth_test_results.csv")
TARGET = build_target("microsoft")

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


def run_nordvpn(*args):
    """
    Run NordVPN without logging stdout/stderr.

    NordVPN CLI syntax used here is compatible with commands such as:
        nordvpn c Dallas
        nordvpn c Canada
        nordvpn status
    """
    try:
        result = subprocess.run(
            ["nordvpn", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def rotate_vpn(location):
    print(f"\nConnecting NordVPN to: {location}")

    if not run_nordvpn("c", location):
        raise RuntimeError(
            f"NordVPN could not connect to requested location: {location}"
        )

    # Give the tunnel/routes a moment to settle.
    time.sleep(4)


def get_public_ip():
    """
    Fetch only the current public IP.

    No authentication information is sent to this endpoint.
    """
    try:
        request = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={
                "User-Agent": "entra-siem-auth-test/1.0",
                "Accept": "application/json",
            },
        )

        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        return data.get("ip", "unknown")
    except Exception:
        return "unknown"


def initialize_log():
    if LOG_FILE.exists():
        return

    with LOG_FILE.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
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
            ],
        )
        writer.writeheader()


def write_log(record):
    """
    Only explicitly approved non-sensitive fields can reach disk.
    Passwords are never accepted by this function.
    """
    allowed = {
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
    }

    record = {key: record.get(key, "") for key in allowed}

    with LOG_FILE.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
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
            ],
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


def prepare_username_page(page, target):
    """
    Get Microsoft back to an account/username selection state while
    preserving the existing browser context, cookies and storage.
    """
    page.goto(
        target.start_url,
        wait_until="domcontentloaded",
        timeout=60000,
    )

    if target.name == "local":
        return

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
    email_box = page.locator("#i0116")

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


def enter_username(page, target, username):
    email = page.locator(target.username_selector)
    email.wait_for(state="visible", timeout=20000)

    email.fill(username)

    if target.name == "local":
        return

    submit = page.locator(target.submit_selector)
    submit.click(timeout=10000)

    password = page.locator(target.password_selector)
    password.wait_for(state="visible", timeout=20000)


def enter_password(page, target, password):
    password_box = page.locator(target.password_selector)

    # Password exists only in memory long enough to fill the browser form.
    password_box.fill(password)

    submit = page.locator(target.submit_selector)

    with page.expect_response(
        lambda response: is_authentication_response(
            target,
            response.request.method,
            response.url,
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


def determine_result(page, target):
    """
    Detect common Microsoft outcomes without dumping page content.

    Attempts 1-9 are expected to fail.
    Attempt 10 is expected to succeed.
    """
    return classify_outcome(
        target,
        page.url,
        safe_body_text(page),
    )


def wait_for_auth_result(page, target):
    deadline = time.time() + 20

    result = "unknown"

    while time.time() < deadline:
        result = determine_result(page, target)

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
                    rotate_vpn(location)
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

                public_ip = get_public_ip()

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

                try:
                    prepare_username_page(page, TARGET)
                    enter_username(page, TARGET, username)
                    auth_response = enter_password(
                        page,
                        TARGET,
                        password,
                    )

                    current_metadata = {
                        "http_status": auth_response.status,
                        "request_id": None,
                        "correlation_id": None,
                    }
                    update_from_headers(
                        current_metadata,
                        auth_response.headers,
                    )

                    # Remove the Python reference immediately after use.
                    password = None

                    result = wait_for_auth_result(page, TARGET)

                    (
                        microsoft_code,
                        page_correlation_id,
                        page_request_id,
                    ) = collect_page_identifiers(page)

                except PlaywrightTimeoutError:
                    # Do not print Playwright exception messages because
                    # browser automation errors may contain page details.
                    password = None
                    result = "timeout"
                    current_metadata = {
                        "http_status": None,
                        "request_id": None,
                        "correlation_id": None,
                    }

                except Exception:
                    # Never serialize exception messages or traceback data.
                    password = None
                    result = "browser_error"
                    current_metadata = {
                        "http_status": None,
                        "request_id": None,
                        "correlation_id": None,
                    }

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

                if microsoft_code:
                    print(f"Microsoft result code: {microsoft_code}")

                if correlation_id:
                    print(f"Correlation ID: {correlation_id}")

                if request_id:
                    print(f"Request ID: {request_id}")

                if attempt < 10:
                    input(
                        "Press Enter when ready for the next attempt..."
                    )

            print(f"\nTest complete. Metadata saved to {LOG_FILE}")

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
    main()
