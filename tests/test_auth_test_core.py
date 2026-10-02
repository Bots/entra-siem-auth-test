import unittest

from auth_test_core import (
    build_target,
    classify_outcome,
    is_authentication_response,
    parse_nordvpn_status,
    public_ip_changed,
    vpn_location_matches,
)


class TargetConfigurationTests(unittest.TestCase):
    def test_local_target_uses_test_server_contract(self):
        target = build_target("local", "http://127.0.0.1:9000/")

        self.assertEqual(target.start_url, "http://127.0.0.1:9000/")
        self.assertEqual(target.username_selector, "#username")
        self.assertEqual(target.password_selector, "#password")
        self.assertEqual(target.submit_selector, "button[type='submit']")

    def test_microsoft_target_uses_entra_contract(self):
        target = build_target("microsoft")

        self.assertEqual(target.start_url, "https://myapps.microsoft.com/")
        self.assertEqual(target.username_selector, "#i0116")
        self.assertEqual(target.password_selector, "#i0118")
        self.assertEqual(target.submit_selector, "#idSIButton9")

    def test_unknown_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported authentication target"):
            build_target("unknown")


class OutcomeClassificationTests(unittest.TestCase):
    def test_local_success_requires_success_path(self):
        target = build_target("local")

        self.assertEqual(
            classify_outcome(target, "http://127.0.0.1:8000/login-success", ""),
            "succeeded",
        )
        self.assertEqual(
            classify_outcome(target, "http://127.0.0.1:8000/unrelated", ""),
            "unknown",
        )

    def test_microsoft_mfa_is_not_success(self):
        target = build_target("microsoft")

        self.assertEqual(
            classify_outcome(
                target,
                "https://login.microsoftonline.com/common/SAS/BeginAuth",
                "Approve sign in request",
            ),
            "mfa_required",
        )

    def test_microsoft_success_requires_known_authenticated_host(self):
        target = build_target("microsoft")

        self.assertEqual(
            classify_outcome(target, "https://myapps.microsoft.com/", ""),
            "succeeded",
        )
        self.assertEqual(
            classify_outcome(target, "https://example.com/redirect", ""),
            "unknown",
        )

    def test_microsoft_conditional_access_is_categorized(self):
        target = build_target("microsoft")

        self.assertEqual(
            classify_outcome(
                target,
                "https://login.microsoftonline.com/common/login",
                "AADSTS53003: Access has been blocked by Conditional Access policies.",
            ),
            "conditional_access",
        )


class AuthenticationResponseTests(unittest.TestCase):
    def test_local_only_matches_login_post(self):
        target = build_target("local", "http://127.0.0.1:8000/")

        self.assertTrue(
            is_authentication_response(
                target,
                "POST",
                "http://127.0.0.1:8000/login",
            )
        )
        self.assertFalse(
            is_authentication_response(
                target,
                "GET",
                "http://127.0.0.1:8000/login-success",
            )
        )

    def test_microsoft_matches_process_auth_post(self):
        target = build_target("microsoft")

        self.assertTrue(
            is_authentication_response(
                target,
                "POST",
                "https://login.microsoftonline.com/common/SAS/ProcessAuth",
            )
        )
        self.assertFalse(
            is_authentication_response(
                target,
                "GET",
                "https://login.microsoftonline.com/common/SAS/ProcessAuth",
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
