"""Pure configuration and classification helpers for authentication tests."""

from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


@dataclass(frozen=True)
class TargetConfig:
    """Browser selectors and endpoint rules for one authentication target."""

    name: str
    start_url: str
    username_selector: str
    password_selector: str
    submit_selector: str


def build_target(name, start_url=None):
    """Build a supported authentication target configuration."""

    normalized_name = name.strip().lower()

    if normalized_name == "local":
        return TargetConfig(
            name="local",
            start_url=start_url or "http://127.0.0.1:8000/",
            username_selector="#username",
            password_selector="#password",
            submit_selector="button[type='submit']",
        )

    if normalized_name == "microsoft":
        return TargetConfig(
            name="microsoft",
            start_url=start_url or "https://myapps.microsoft.com/",
            username_selector="#i0116",
            password_selector="#i0118",
            submit_selector="#idSIButton9",
        )

    raise ValueError(f"Unsupported authentication target: {name}")


def classify_outcome(target, url, visible_text):
    """Return a positive, categorized result from URL and visible markers."""

    parsed_url = urlparse(url)
    path = parsed_url.path.rstrip("/").lower()
    hostname = (parsed_url.hostname or "").lower()
    body = visible_text.lower()

    if target.name == "local":
        if path == "/login-success":
            return "succeeded"
        if path == "/login-failed":
            return "failed"
        return "unknown"

    categorized_markers = (
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
            (
                "permissions requested",
                "accept permissions",
                "review permissions",
            ),
        ),
        (
            "password_change_required",
            (
                "update your password",
                "change your password",
                "password has expired",
            ),
        ),
        (
            "account_locked",
            (
                "aadsts50053",
                "account has been locked",
            ),
        ),
        (
            "throttled",
            (
                "too many attempts",
                "temporarily locked",
                "try again later",
            ),
        ),
        (
            "challenge_required",
            (
                "captcha",
                "prove you are human",
            ),
        ),
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

    for result, markers in categorized_markers:
        if any(marker in body for marker in markers):
            return result

    if hostname in {
        "myapps.microsoft.com",
        "myapplications.microsoft.com",
    }:
        return "succeeded"

    return "unknown"


def is_authentication_response(target, method, url):
    """Identify only the response to an authentication form submission."""

    if method.upper() != "POST":
        return False

    target_url = urlparse(target.start_url)
    response_url = urlparse(url)

    if target.name == "local":
        return (
            response_url.hostname == target_url.hostname
            and response_url.port == target_url.port
            and response_url.path.rstrip("/").lower() == "/login"
        )

    if (response_url.hostname or "").lower() != "login.microsoftonline.com":
        return False

    path = response_url.path.rstrip("/").lower()
    return path.endswith("/login") or path.endswith("/sas/processauth")


def parse_nordvpn_status(output):
    """Extract only location fields from NordVPN status output."""

    location = {"country": "", "city": ""}

    for line in output.splitlines():
        name, separator, value = line.partition(":")

        if not separator:
            continue

        normalized_name = name.strip().lower()

        if normalized_name in location:
            location[normalized_name] = value.strip()

    return location


def vpn_location_matches(requested_location, actual_location):
    """Verify NordVPN reached the requested city or country."""

    requested = requested_location.replace("_", " ").strip().casefold()
    country_targets = {
        "canada",
        "germany",
        "united kingdom",
    }

    if requested in country_targets:
        return actual_location.get("country", "").strip().casefold() == requested

    return actual_location.get("city", "").strip().casefold() == requested


def public_ip_changed(previous_ip, current_ip):
    """Return true only when both public-IP values are valid and different."""

    try:
        previous = ip_address(previous_ip)
        current = ip_address(current_ip)
    except ValueError:
        return False

    return previous != current
