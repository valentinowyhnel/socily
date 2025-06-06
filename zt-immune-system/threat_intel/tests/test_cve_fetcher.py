import os
import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import logging
import datetime # For date objects in tests
import time # For time.sleep patching

# Make sure the cve_fetcher module can be imported
from zt_immune_system.threat_intel import cve_fetcher

# Disable most logging for cleaner test output, but allow critical errors to show.
logging.disable(logging.CRITICAL)

# Sample NVD API response structures for mocking
SAMPLE_NVD_CVE_ITEM_JSON = {
    "id": "CVE-2023-0001",
    "sourceIdentifier": "cve@mitre.org",
    "published": "2023-01-01T00:00:00.000Z",
    "lastModified": "2023-01-02T00:00:00.000Z",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "English description of CVE-2023-0001."},
        {"lang": "es", "value": "Spanish description."}
    ],
    "metrics": {
        "cvssMetricV31": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
                "exploitabilityScore": 3.9, # Included for parsing test
                "impactScore": 5.9          # Included for parsing test
            }
        }],
        "cvssMetricV2": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {
                "version": "2.0",
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "baseScore": 7.5
                # baseSeverity for V2 is often outside cvssData in NVD's main metric obj
            },
            "baseSeverity": "HIGH",
            "exploitabilityScore": 10.0,
            "impactScore": 6.4,
        }]
    },
    "weaknesses": [{
        "source": "nvd@nist.gov",
        "type": "Primary", # This 'type' refers to the weakness classification, not CWE itself
        "description": [{"lang": "en", "value": "CWE-79"}] # 'value' contains the CWE ID
    }],
    "references": [
        {"url": "http://example.com/ref1", "source": "example.com", "tags": ["Third Party Advisory"]},
        {"url": "http://example.com/ref2", "source": "example.com"} # No tags
    ]
}

SAMPLE_NVD_API_RESPONSE_SINGLE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2023-10-27T15:00:00.000Z",
    "vulnerabilities": [{"cve": SAMPLE_NVD_CVE_ITEM_JSON}]
}

SAMPLE_NVD_API_RESPONSE_EMPTY = {
    "resultsPerPage": 0, "startIndex": 0, "totalResults": 0,
    "vulnerabilities": []
}


class TestNVDAPICall(unittest.TestCase):
    """Tests for the _call_nvd_api helper function."""

    original_nvd_api_key = None

    @classmethod
    def setUpClass(cls):
        # Store original NVD_API_KEY value if it exists, to restore after tests
        cls.original_nvd_api_key = cve_fetcher.NVD_API_KEY

    @classmethod
    def tearDownClass(cls):
        # Restore original NVD_API_KEY
        cve_fetcher.NVD_API_KEY = cls.original_nvd_api_key
        # This also implies os.environ should be reset if modified, but patch.dict handles that per test.

    def setUp(self):
        # Default NVD_API_KEY to None for most tests, can be overridden with patch.dict
        cve_fetcher.NVD_API_KEY = None


    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_success_no_key(self, mock_requests_get):
        """Test successful API call without an API key."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_requests_get.return_value = mock_response

        # Ensure NVD_API_KEY is None for this specific test context
        cve_fetcher.NVD_API_KEY = None
        result = cve_fetcher._call_nvd_api(params={"someParam": "value"})

        self.assertEqual(result, {"status": "ok"})
        mock_requests_get.assert_called_once_with(
            cve_fetcher.NVD_API_BASE_URL,
            headers={},
            params={"someParam": "value"},
            timeout=cve_fetcher.REQUEST_TIMEOUT_SECONDS
        )

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_success_with_key(self, mock_requests_get):
        """Test successful API call with an API key."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok_key"}
        mock_requests_get.return_value = mock_response

        cve_fetcher.NVD_API_KEY = "test_key_123" # Set for this test context
        result = cve_fetcher._call_nvd_api(params={"param": "val"})

        self.assertEqual(result, {"status": "ok_key"})
        mock_requests_get.assert_called_once_with(
            cve_fetcher.NVD_API_BASE_URL,
            headers={'apiKey': 'test_key_123'},
            params={"param": "val"},
            timeout=cve_fetcher.REQUEST_TIMEOUT_SECONDS
        )

    @patch('zt_immune_system.threat_intel.cve_fetcher.time.sleep', return_value=None) # Mock sleep
    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_rate_limit_no_key_retries_and_fails(self, mock_requests_get, mock_sleep):
        """Test rate limiting (403) without API key, retries, then fails."""
        mock_response_403 = MagicMock(spec=requests.Response) # Use spec for better mocking
        mock_response_403.status_code = 403
        mock_response_403.text = "Rate limit exceeded without API Key"
        # Simulate raise_for_status() behavior for a 403 error
        mock_response_403.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response_403)
        mock_requests_get.return_value = mock_response_403

        cve_fetcher.NVD_API_KEY = None # Ensure no key for this test
        result = cve_fetcher._call_nvd_api()

        self.assertIsNone(result)
        self.assertEqual(mock_requests_get.call_count, cve_fetcher.MAX_RETRIES)
        self.assertEqual(mock_sleep.call_count, cve_fetcher.MAX_RETRIES - 1)

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_rate_limit_with_key_fails_no_retry(self, mock_requests_get):
        """Test 403 with API key (implies bad key or quota), fails without retry."""
        mock_response_403 = MagicMock(spec=requests.Response)
        mock_response_403.status_code = 403
        mock_response_403.text = "Forbidden - API key issue or quota exceeded"
        mock_response_403.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response_403)
        mock_requests_get.return_value = mock_response_403

        cve_fetcher.NVD_API_KEY = "bad_or_exhausted_key" # Set for this test
        result = cve_fetcher._call_nvd_api()

        self.assertIsNone(result)
        mock_requests_get.assert_called_once() # Should not retry if API key is present and 403 occurs

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_http_404_error(self, mock_requests_get):
        """Test HTTP 404 Not Found error (no retry)."""
        mock_response_404 = MagicMock(spec=requests.Response)
        mock_response_404.status_code = 404
        mock_response_404.text = "CVE Not Found"
        mock_response_404.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response_404)
        mock_requests_get.return_value = mock_response_404

        result = cve_fetcher._call_nvd_api(cve_id="CVE-DOES-NOT-EXIST")
        self.assertIsNone(result)
        # Check the URL construction for CVE ID
        expected_url = f"{cve_fetcher.NVD_API_BASE_URL}/CVE-DOES-NOT-EXIST"
        mock_requests_get.assert_called_once_with(
            expected_url, headers={}, params=None, timeout=cve_fetcher.REQUEST_TIMEOUT_SECONDS
        )

    @patch('zt_immune_system.threat_intel.cve_fetcher.time.sleep', return_value=None)
    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_timeout_retries_and_fails(self, mock_requests_get, mock_sleep):
        """Test requests.exceptions.Timeout, retries with backoff, then fails."""
        mock_requests_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        result = cve_fetcher._call_nvd_api()

        self.assertIsNone(result)
        self.assertEqual(mock_requests_get.call_count, cve_fetcher.MAX_RETRIES)
        self.assertEqual(mock_sleep.call_count, cve_fetcher.MAX_RETRIES - 1)
        # Check if sleep was called with increasing delays (simplified check for calls)
        self.assertTrue(mock_sleep.call_args_list[0][0][0] < mock_sleep.call_args_list[1][0][0] if cve_fetcher.MAX_RETRIES > 2 else True)


    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_json_decode_error(self, mock_requests_get):
        """Test ValueError (JSONDecodeError) when parsing response."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "This is not valid JSON" # Provide text for logging
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_requests_get.return_value = mock_response

        result = cve_fetcher._call_nvd_api()
        self.assertIsNone(result)
        mock_response.json.assert_called_once()


class TestParseNVDCVEItem(unittest.TestCase):
    """Tests for the _parse_nvd_cve_item function."""

    def test_parse_full_cve_item(self):
        """Test parsing a complete, valid CVE item from NVD JSON."""
        # Use a copy to avoid modification if tests change the sample dict
        sample_data = SAMPLE_NVD_CVE_ITEM_JSON.copy()
        parsed_cve = cve_fetcher._parse_nvd_cve_item(sample_data)

        self.assertIsNotNone(parsed_cve)
        self.assertEqual(parsed_cve.id, "CVE-2023-0001")
        self.assertEqual(parsed_cve.source_identifier, "cve@mitre.org")
        self.assertEqual(parsed_cve.published_date, "2023-01-01T00:00:00.000Z")
        self.assertEqual(parsed_cve.last_modified_date, "2023-01-02T00:00:00.000Z")
        self.assertEqual(parsed_cve.vuln_status, "Analyzed")

        self.assertEqual(len(parsed_cve.descriptions), 2)
        self.assertEqual(parsed_cve.get_english_description(), "English description of CVE-2023-0001.")

        self.assertTrue("cvssMetricV31" in parsed_cve.metrics)
        self.assertEqual(len(parsed_cve.metrics["cvssMetricV31"]), 1)
        cvss_v31 = parsed_cve.metrics["cvssMetricV31"][0]
        self.assertEqual(cvss_v31.version, "3.1")
        self.assertEqual(cvss_v31.base_score, 9.8)
        self.assertEqual(cvss_v31.base_severity, "CRITICAL")
        self.assertEqual(cvss_v31.source, "nvd@nist.gov")
        self.assertEqual(cvss_v31.cvss_type, "Primary")
        self.assertEqual(cvss_v31.exploitability_score, 3.9) # Check optional field
        self.assertEqual(cvss_v31.impact_score, 5.9)          # Check optional field

        self.assertTrue("cvssMetricV2" in parsed_cve.metrics)
        cvss_v2 = parsed_cve.metrics["cvssMetricV2"][0]
        self.assertEqual(cvss_v2.version, "2.0") # NVD CVSS V2 version is string "2.0"
        self.assertEqual(cvss_v2.base_score, 7.5)
        self.assertEqual(cvss_v2.base_severity, "HIGH") # Parsed from metric_data_item for v2

        self.assertEqual(len(parsed_cve.weaknesses), 1)
        self.assertEqual(parsed_cve.weaknesses[0].cwe_id, "CWE-79")
        self.assertEqual(parsed_cve.weaknesses[0].description, "Primary") # 'type' from weakness_entry

        self.assertEqual(len(parsed_cve.references), 2)
        self.assertEqual(parsed_cve.references[0].url, "http://example.com/ref1")
        self.assertEqual(parsed_cve.references[0].tags, ["Third Party Advisory"])
        self.assertEqual(parsed_cve.references[1].tags, []) # Should default to empty list


    def test_parse_minimal_cve_item(self):
        """Test parsing a CVE item with only mandatory 'id' and 'descriptions'."""
        minimal_data = {
            "id": "CVE-2023-0002",
            "descriptions": [{"lang": "en", "value": "Minimal description."}]
            # All other fields (metrics, weaknesses, references, etc.) are optional
        }
        parsed_cve = cve_fetcher._parse_nvd_cve_item(minimal_data)
        self.assertIsNotNone(parsed_cve)
        self.assertEqual(parsed_cve.id, "CVE-2023-0002")
        self.assertEqual(parsed_cve.get_english_description(), "Minimal description.")
        self.assertEqual(len(parsed_cve.metrics), 0) # Should be empty dict
        self.assertEqual(len(parsed_cve.weaknesses), 0) # Should be empty list
        self.assertEqual(len(parsed_cve.references), 0) # Should be empty list
        self.assertIsNone(parsed_cve.vuln_status) # Optional field

    def test_parse_cve_item_missing_key_id_fails(self):
        """Test parsing fails if the mandatory 'id' key is missing."""
        invalid_data = {"descriptions": [{"lang": "en", "value": "CVE without an ID."}]}
        # This should log a KeyError and return None
        with self.assertLogs(logger=cve_fetcher.logger, level='ERROR') as log_cm:
            parsed_cve = cve_fetcher._parse_nvd_cve_item(invalid_data)
        self.assertIsNone(parsed_cve)
        self.assertTrue(any("KeyError" in msg and "'id'" in msg for msg in log_cm.output))


    def test_parse_cve_item_invalid_input_data_type(self):
        """Test parsing fails gracefully if input is not a dictionary."""
        with self.assertLogs(logger=cve_fetcher.logger, level='ERROR') as log_cm:
            parsed_cve = cve_fetcher._parse_nvd_cve_item("this_is_not_a_dictionary") # type: ignore
        self.assertIsNone(parsed_cve)
        self.assertTrue(any("Invalid cve_data provided to parser" in msg for msg in log_cm.output))


# Placeholder for TestFetchCveById, TestFetchCvesByTimeWindow, TestSaveCvesToJson

if __name__ == '__main__':
    unittest.main()
