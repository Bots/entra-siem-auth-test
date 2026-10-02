import os
import json
import tempfile
import unittest
from pathlib import Path

TEST_USERNAME = "test@example.invalid"
TEST_PASSWORD = "synthetic-test-password"

os.environ["TEST_USERNAME"] = TEST_USERNAME
os.environ["TEST_PASSWORD"] = TEST_PASSWORD
os.environ["SESSION_SECRET"] = "synthetic-session-secret-long-enough-for-tests"

import auth_test_server
from auth_test_server import AttemptRateLimiter


class ServerConfigTests(unittest.TestCase):
    def test_loopback_server_runs_with_safe_local_defaults(self):
        config, credentials = auth_test_server.load_server_config({})

        self.assertEqual(config["host"], "127.0.0.1")
        self.assertGreaterEqual(len(config["session_secret"]), 32)
        self.assertEqual(credentials[0][0], "test@example.com")

    def test_supports_nine_test_users(self):
        users = [
            {
                "username": f"user{number}@example.invalid",
                "password": f"synthetic-password-{number}",
            }
            for number in range(1, 10)
        ]
        config, credentials = auth_test_server.load_server_config(
            {
                "TEST_USERNAME": json.dumps(users),
                "SESSION_SECRET": "synthetic-session-secret-long-enough-for-tests",
            }
        )

        self.assertEqual(len(credentials), 9)
        self.assertEqual(credentials[0], (users[0]["username"], users[0]["password"]))
        self.assertNotIn("password", config)

    def test_rejects_weak_session_secret(self):
        with self.assertRaisesRegex(ValueError, "at least 32"):
            auth_test_server.load_server_config(
                {
                    "TEST_USERNAME": TEST_USERNAME,
                    "TEST_PASSWORD": TEST_PASSWORD,
                    "SESSION_SECRET": "too-short",
                }
            )

    def test_remote_bind_requires_https_cookie(self):
        with self.assertRaisesRegex(ValueError, "SESSION_HTTPS_ONLY"):
            auth_test_server.load_server_config(
                {
                    "TEST_USERNAME": TEST_USERNAME,
                    "TEST_PASSWORD": TEST_PASSWORD,
                    "SESSION_SECRET": "synthetic-session-secret-long-enough-for-tests",
                    "AUTH_HOST": "0.0.0.0",
                }
            )

    def test_remote_bind_requires_explicit_session_secret(self):
        with self.assertRaisesRegex(ValueError, "SESSION_SECRET"):
            auth_test_server.load_server_config(
                {
                    "TEST_USERNAME": TEST_USERNAME,
                    "TEST_PASSWORD": TEST_PASSWORD,
                    "AUTH_HOST": "0.0.0.0",
                    "SESSION_HTTPS_ONLY": "true",
                }
            )


class AttemptRateLimiterTests(unittest.TestCase):
    def test_rejects_second_attempt_within_one_second(self):
        limiter = AttemptRateLimiter(minimum_interval_seconds=1.0)

        self.assertTrue(limiter.allow("source/session", now=10.0))
        self.assertFalse(limiter.allow("source/session", now=10.999))
        self.assertTrue(limiter.allow("source/session", now=11.0))

    def test_tracks_clients_independently(self):
        limiter = AttemptRateLimiter(minimum_interval_seconds=1.0)

        self.assertTrue(limiter.allow("client-a", now=10.0))
        self.assertTrue(limiter.allow("client-b", now=10.1))

    def test_bounds_and_expires_client_state(self):
        limiter = AttemptRateLimiter(
            minimum_interval_seconds=1.0,
            max_keys=2,
        )

        self.assertTrue(limiter.allow("client-a", now=10.0))
        self.assertTrue(limiter.allow("client-b", now=10.1))
        self.assertTrue(limiter.allow("client-c", now=10.2))
        self.assertLessEqual(len(limiter._last_attempt), 2)

        self.assertTrue(limiter.allow("client-d", now=12.0))
        self.assertEqual(len(limiter._last_attempt), 1)


class AuthenticationLoggingTests(unittest.TestCase):
    def test_log_uses_allowlist_and_never_serializes_password(self):
        sentinel_password = "SENTINEL-PASSWORD-MUST-NOT-LEAK"

        with tempfile.TemporaryDirectory() as directory:
            original_log_file = auth_test_server.LOG_FILE
            auth_test_server.LOG_FILE = Path(directory) / "events.jsonl"

            try:
                auth_test_server.log_auth_event(
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "username": "test@example.invalid",
                        "source_ip": "192.0.2.1",
                        "user_agent": "synthetic-agent",
                        "session_id": "session-1",
                        "request_id": "request-1",
                        "http_status": 303,
                        "result": "failure",
                        "password": sentinel_password,
                        "unexpected": "discard-me",
                    }
                )

                serialized = auth_test_server.LOG_FILE.read_text()
                event = json.loads(serialized)
            finally:
                auth_test_server.LOG_FILE = original_log_file

        self.assertNotIn(sentinel_password, serialized)
        self.assertNotIn("password", event)
        self.assertNotIn("unexpected", event)
        self.assertEqual(
            set(event),
            {
                "timestamp",
                "username",
                "source_ip",
                "user_agent",
                "session_id",
                "request_id",
                "http_status",
                "result",
            },
        )

    def test_session_id_is_stable_for_one_browser_session(self):
        class FakeRequest:
            def __init__(self):
                self.session = {}

        request = FakeRequest()

        first = auth_test_server.get_or_create_session_id(request)
        second = auth_test_server.get_or_create_session_id(request)

        self.assertEqual(first, second)

    def test_authentication_accepts_only_the_configured_password(self):
        self.assertTrue(
            auth_test_server.authenticate(
                TEST_USERNAME,
                TEST_PASSWORD,
            )
        )
        self.assertFalse(
            auth_test_server.authenticate(
                TEST_USERNAME,
                "incorrect-password",
            )
        )


if __name__ == "__main__":
    unittest.main()
