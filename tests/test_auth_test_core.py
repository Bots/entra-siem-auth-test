import unittest

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


class MicrosoftFlowTests(unittest.TestCase):
    def test_uses_expected_microsoft_entrypoint_and_selectors(self):
        self.assertEqual(MICROSOFT_START_URL, "https://myapps.microsoft.com/")
        self.assertEqual(USERNAME_SELECTOR, "#i0116")
        self.assertEqual(PASSWORD_SELECTOR, "#i0118")
        self.assertEqual(SUBMIT_SELECTOR, "#idSIButton9")

    def test_mfa_is_not_success(self):
        self.assertEqual(
            classify_outcome(
                "https://login.microsoftonline.com/common/SAS/BeginAuth",
                "Approve sign in request",
            ),
            "mfa_required",
        )

    def test_success_requires_known_authenticated_host(self):
        self.assertEqual(
            classify_outcome("https://myapps.microsoft.com/", ""),
            "succeeded",
        )
        self.assertEqual(
            classify_outcome("https://example.com/redirect", ""),
            "unknown",
        )

    def test_conditional_access_is_categorized(self):
        self.assertEqual(
            classify_outcome(
                "https://login.microsoftonline.com/common/login",
                "AADSTS53003: Access has been blocked by Conditional Access policies.",
            ),
            "conditional_access",
        )

    def test_matches_only_known_authentication_navigation_posts(self):
        self.assertTrue(
            is_authentication_response(
                "POST",
                "https://login.microsoftonline.com/common/SAS/ProcessAuth",
            )
        )
        self.assertFalse(
            is_authentication_response(
                "GET",
                "https://login.microsoftonline.com/common/SAS/ProcessAuth",
            )
        )
        self.assertFalse(
            is_authentication_response(
                "POST",
                "https://login.microsoftonline.com/common/telemetry",
            )
        )
        self.assertFalse(
            is_authentication_response(
                "POST",
                "https://login.microsoftonline.com/common/login",
                is_navigation_request=False,
            )
        )


class VpnVerificationTests(unittest.TestCase):
    def test_parses_only_country_and_city_from_status(self):
        status = """Status: Connected
Hostname: us1234.nordvpn.com
IP: 203.0.113.8
Country: United States
City: Dallas
"""
        self.assertEqual(
            parse_nordvpn_status(status),
            {"country": "United States", "city": "Dallas"},
        )

    def test_city_and_country_targets_are_verified(self):
        self.assertTrue(
            vpn_location_matches(
                "Dallas",
                {"country": "United States", "city": "Dallas"},
            )
        )
        self.assertTrue(
            vpn_location_matches(
                "United_Kingdom",
                {"country": "United Kingdom", "city": "London"},
            )
        )
        self.assertFalse(
            vpn_location_matches(
                "Dallas",
                {"country": "United States", "city": "Houston"},
            )
        )

    def test_public_ip_must_be_valid_and_change(self):
        self.assertTrue(public_ip_changed("198.51.100.1", "198.51.100.2"))
        self.assertFalse(public_ip_changed("198.51.100.1", "198.51.100.1"))
        self.assertFalse(public_ip_changed("unknown", "198.51.100.2"))
        self.assertFalse(public_ip_changed("198.51.100.1", "unknown"))


if __name__ == "__main__":
    unittest.main()
