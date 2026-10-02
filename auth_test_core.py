"""Pure helpers for the Microsoft Entra authentication test."""

from ipaddress import ip_address
from urllib.parse import urlparse

MICROSOFT_START_URL = "https://myapps.microsoft.com/"
USERNAME_SELECTOR = "#i0116"
PASSWORD_SELECTOR = "#i0118"
SUBMIT_SELECTOR = "#idSIButton9"

OUTCOME_MARKERS = (
    (
        "conditional_access",
        (
            "aadsts53003",
            "conditional access",
            "you can't get there from here",
            "you couldn’t get there from here",
            "access has been blocked",
        ),
    ),
    (
        "mfa_required",
        (
            "approve sign in request",
            "approve a request on my microsoft authenticator app",
            "verify your identity",
            "enter code",
            "enter the code displayed",
        ),
    ),
    (
        "consent_required",
        ("permissions requested", "accept permissions", "review permissions"),
    ),
    (
        "password_change_required",
        ("update your password", "change your password", "password has expired"),
    ),
    ("account_locked", ("aadsts50053", "account has been locked")),
    (
        "throttled",
        ("too many attempts", "temporarily locked", "try again later"),
    ),
    ("challenge_required", ("captcha", "prove you are human")),
    (
        "failed",
        (
            "aadsts50126",
            "your account or password is incorrect",
            "password is incorrect",
            "incorrect password",
            "enter a valid password",
            "we couldn't sign you in",
            "we couldn’t sign you in",
        ),
    ),
)


def classify_outcome(url, visible_text):
    """Classify Microsoft authentication using positive URL/text markers."""

    hostname = (urlparse(url).hostname or "").lower()
    body = visible_text.lower()

    for result, markers in OUTCOME_MARKERS:
        if any(marker in body for marker in markers):
            return result

    if hostname in {"myapps.microsoft.com", "myapplications.microsoft.com"}:
        return "succeeded"

    return "unknown"


def is_authentication_response(method, url, is_navigation_request=True):
    """Match Microsoft credential-submission navigation responses."""

    if method.upper() != "POST" or not is_navigation_request:
        return False

    parsed = urlparse(url)
    path = parsed.path.rstrip("/").lower()

    return (
        (parsed.hostname or "").lower() == "login.microsoftonline.com"
        and (
            path.endswith("/login")
            or path.endswith("/sas/processauth")
            or path.endswith("/login.srf")
        )
    )


def parse_nordvpn_status(output):
    """Extract only country and city from NordVPN status output."""

    location = {"country": "", "city": ""}

    for line in output.splitlines():
        name, separator, value = line.partition(":")
        normalized_name = name.strip().lower()

        if separator and normalized_name in location:
            location[normalized_name] = value.strip()

    return location


def vpn_location_matches(requested_location, actual_location):
    """Verify NordVPN reached the requested city or country."""

    requested = requested_location.replace("_", " ").strip().casefold()

    if requested in {"canada", "germany", "united kingdom"}:
        return actual_location.get("country", "").strip().casefold() == requested

    return actual_location.get("city", "").strip().casefold() == requested


def public_ip_changed(previous_ip, current_ip):
    """Return true only when both IP values are valid and different."""

    try:
        return ip_address(previous_ip) != ip_address(current_ip)
    except ValueError:
        return False
