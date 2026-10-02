import os
import unittest

os.environ.setdefault("TEST_USERNAME", "test@example.invalid")
os.environ.setdefault("TEST_PASSWORD", "synthetic-test-password")
os.environ.setdefault("SESSION_SECRET", "synthetic-session-secret-long-enough-for-tests")

from auth_test_server import AttemptRateLimiter


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


if __name__ == "__main__":
    unittest.main()
