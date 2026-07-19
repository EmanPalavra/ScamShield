import unittest
from unittest.mock import patch

import app as scamshield


class ScamShieldRouteTests(unittest.TestCase):
    def setUp(self):
        scamshield.app.config.update(TESTING=True)
        self.client = scamshield.app.test_client()

    def provider_mocks(self):
        return patch.multiple(
            scamshield,
            google_safe_browsing_check=lambda _url: (False, "Google Safe Browsing test result."),
            phishtank_check=lambda _url: (False, "PhishTank test result."),
            domain_age_check=lambda _domain: (3650, 0.08, "Domain age test result."),
            virus_total_check=lambda _url: (
                0.84,
                {"malicious": 1, "suspicious": 0, "harmless": 70},
                "VirusTotal test result: 1 malicious detection.",
            ),
        )

    def test_deep_scan_works_without_quick_scan_first(self):
        message = "Urgent: verify this suspicious link https://paypaI-security-login.com now."

        with self.provider_mocks():
            response = self.client.post(
                "/deep",
                data={"message": message, "view_mode": "analyst"},
            )

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Deep Scan completed", page)
        self.assertIn("VirusTotal test result: 1 malicious detection.", page)
        self.assertIn(message, page)
        self.assertIn("Evidence Breakdown", page)

    def test_scan_page_uses_one_form_for_both_scan_modes(self):
        response = self.client.get("/")
        page = response.get_data(as_text=True)

        self.assertEqual(page.count('class="scan-form"'), 1)
        self.assertIn('formaction="/deep"', page)
        self.assertIn("Deep Scan works independently", page)

    def test_empty_scan_returns_a_clear_validation_message(self):
        response = self.client.post("/deep", data={"message": "", "view_mode": "simple"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Paste a message or link before starting a scan.", response.get_data(as_text=True))

    def test_message_length_is_enforced_server_side(self):
        too_long = "x" * (scamshield.MAX_MESSAGE_LENGTH + 1)
        response = self.client.post("/", data={"message": too_long, "view_mode": "simple"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("The input is too long", response.get_data(as_text=True))

    def test_health_check_and_security_headers(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("form-action 'self'", response.headers["Content-Security-Policy"])

    def test_google_safe_browsing_uses_v5_and_caches_the_result(self):
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return {"threats": [{"url": "https://example.test"}], "cacheDuration": "60s"}

        scamshield.SAFE_BROWSING_CACHE.clear()
        with patch.object(scamshield, "GOOGLE_API_KEY", "test-key"), patch.object(
            scamshield.requests, "get", return_value=FakeResponse()
        ) as mocked_get:
            first = scamshield.google_safe_browsing_check("https://example.test")
            second = scamshield.google_safe_browsing_check("https://example.test")

        self.assertTrue(first[0])
        self.assertEqual(first, second)
        self.assertEqual(mocked_get.call_count, 1)
        self.assertIn("/v5/urls:search", mocked_get.call_args.args[0])

    def test_phishtank_http_lookup_is_disabled_by_default(self):
        with patch.object(scamshield, "PHISHTANK_API_KEY", "test-key"), patch.object(
            scamshield, "ALLOW_INSECURE_PHISHTANK", False
        ), patch.object(scamshield.requests, "post") as mocked_post:
            result = scamshield.phishtank_check("https://example.test")

        self.assertIsNone(result[0])
        self.assertIn("unencrypted HTTP", result[1])
        mocked_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
