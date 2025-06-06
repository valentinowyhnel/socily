import os
import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import logging
import datetime # For date objects in tests
import time # For time.sleep patching
import json # For save_cves_to_json tests

# Make sure the cve_fetcher module can be imported
from zt_immune_system.threat_intel import cve_fetcher
from zt_immune_system.threat_intel.cve_fetcher import CVEDetail, CVEDescription, CVSSMetric # Import dataclasses for constructing test objects

# Disable most logging for cleaner test output, but allow critical errors to show.
logging.disable(logging.CRITICAL)

# Sample NVD API response structures for mocking (copied from previous state)
SAMPLE_NVD_CVE_ITEM_JSON = {
    "id": "CVE-2023-0001", "sourceIdentifier": "cve@mitre.org", "published": "2023-01-01T00:00:00.000Z",
    "lastModified": "2023-01-02T00:00:00.000Z", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "English description of CVE-2023-0001."}],
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "baseScore": 9.8, "baseSeverity": "CRITICAL", "exploitabilityScore": 3.9, "impactScore": 5.9}}]},
    "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}],
    "references": [{"url": "http://example.com/ref1", "source": "example.com", "tags": ["Third Party Advisory"]}]
}
SAMPLE_NVD_API_RESPONSE_SINGLE = {"vulnerabilities": [{"cve": SAMPLE_NVD_CVE_ITEM_JSON}], "totalResults": 1}
SAMPLE_NVD_API_RESPONSE_EMPTY = {"vulnerabilities": [], "totalResults": 0}


class TestNVDAPICall(unittest.TestCase):
    # ... (Tests for _call_nvd_api - keep as is from previous step) ...
    original_nvd_api_key = None

    @classmethod
    def setUpClass(cls):
        cls.original_nvd_api_key = cve_fetcher.NVD_API_KEY

    @classmethod
    def tearDownClass(cls):
        cve_fetcher.NVD_API_KEY = cls.original_nvd_api_key

    def setUp(self):
        cve_fetcher.NVD_API_KEY = None

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_success_no_key(self, mock_requests_get):
        mock_response = MagicMock(); mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}; mock_requests_get.return_value = mock_response
        cve_fetcher.NVD_API_KEY = "" # Ensure it's empty for this test
        result = cve_fetcher._call_nvd_api(params={"someParam": "value"})
        self.assertEqual(result, {"status": "ok"})
        mock_requests_get.assert_called_once_with(cve_fetcher.NVD_API_BASE_URL, headers={}, params={"someParam": "value"}, timeout=cve_fetcher.REQUEST_TIMEOUT_SECONDS)

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_success_with_key(self, mock_requests_get):
        mock_response = MagicMock(); mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok_key"}; mock_requests_get.return_value = mock_response
        cve_fetcher.NVD_API_KEY = "test_key_123"
        result = cve_fetcher._call_nvd_api(params={"param": "val"})
        self.assertEqual(result, {"status": "ok_key"})
        mock_requests_get.assert_called_once_with(cve_fetcher.NVD_API_BASE_URL, headers={'apiKey': 'test_key_123'}, params={"param": "val"}, timeout=cve_fetcher.REQUEST_TIMEOUT_SECONDS)

    @patch('zt_immune_system.threat_intel.cve_fetcher.time.sleep', return_value=None)
    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_rate_limit_no_key_retries_and_fails(self, mock_requests_get, mock_sleep):
        mock_response_403 = MagicMock(spec=requests.Response); mock_response_403.status_code = 403; mock_response_403.text = "Rate limit"
        mock_response_403.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response_403)
        mock_requests_get.return_value = mock_response_403
        cve_fetcher.NVD_API_KEY = ""
        result = cve_fetcher._call_nvd_api()
        self.assertIsNone(result); self.assertEqual(mock_requests_get.call_count, cve_fetcher.MAX_RETRIES); self.assertEqual(mock_sleep.call_count, cve_fetcher.MAX_RETRIES - 1)

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_rate_limit_with_key_fails_no_retry(self, mock_requests_get):
        mock_response_403 = MagicMock(spec=requests.Response); mock_response_403.status_code = 403; mock_response_403.text = "Bad key"
        mock_response_403.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response_403)
        mock_requests_get.return_value = mock_response_403
        cve_fetcher.NVD_API_KEY = "bad_key"
        result = cve_fetcher._call_nvd_api()
        self.assertIsNone(result); mock_requests_get.assert_called_once()

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_http_404_error(self, mock_requests_get):
        mock_response_404 = MagicMock(spec=requests.Response); mock_response_404.status_code = 404; mock_response_404.text = "Not Found"
        mock_response_404.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response_404)
        mock_requests_get.return_value = mock_response_404
        result = cve_fetcher._call_nvd_api(cve_id="CVE-NON-EXISTENT")
        self.assertIsNone(result); mock_requests_get.assert_called_once()

    @patch('zt_immune_system.threat_intel.cve_fetcher.time.sleep', return_value=None)
    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_timeout_retries_and_fails(self, mock_requests_get, mock_sleep):
        mock_requests_get.side_effect = requests.exceptions.Timeout("Timed out")
        result = cve_fetcher._call_nvd_api()
        self.assertIsNone(result); self.assertEqual(mock_requests_get.call_count, cve_fetcher.MAX_RETRIES); self.assertEqual(mock_sleep.call_count, cve_fetcher.MAX_RETRIES -1)

    @patch('zt_immune_system.threat_intel.cve_fetcher.requests.get')
    def test_call_nvd_api_json_decode_error(self, mock_requests_get):
        mock_response = MagicMock(spec=requests.Response); mock_response.status_code = 200; mock_response.text = "Invalid JSON"
        mock_response.json.side_effect = ValueError("Invalid JSON"); mock_requests_get.return_value = mock_response
        result = cve_fetcher._call_nvd_api(); self.assertIsNone(result)


class TestParseNVDCVEItem(unittest.TestCase):
    # ... (Tests for _parse_nvd_cve_item - keep as is from previous step) ...
    def test_parse_full_cve_item(self):
        parsed_cve = cve_fetcher._parse_nvd_cve_item(SAMPLE_NVD_CVE_ITEM_JSON)
        self.assertIsNotNone(parsed_cve); self.assertEqual(parsed_cve.id, "CVE-2023-0001")
        self.assertEqual(parsed_cve.get_english_description(), "English description of CVE-2023-0001.")
        cvss_v31 = parsed_cve.get_cvss_v3_metric() # Use helper
        self.assertIsNotNone(cvss_v31); self.assertEqual(cvss_v31.base_score, 9.8)
        self.assertEqual(len(parsed_cve.weaknesses), 1); self.assertEqual(parsed_cve.weaknesses[0].cwe_id, "CWE-79")
        self.assertEqual(len(parsed_cve.references), 1)

    def test_parse_minimal_cve_item(self):
        minimal_data = {"id": "CVE-2023-0002", "descriptions": [{"lang": "en", "value": "Minimal."}]}
        parsed_cve = cve_fetcher._parse_nvd_cve_item(minimal_data)
        self.assertIsNotNone(parsed_cve); self.assertEqual(parsed_cve.id, "CVE-2023-0002")

    def test_parse_cve_item_missing_key_id(self):
        invalid_data = {"descriptions": [{"lang": "en", "value": "No ID."}]}
        self.assertIsNone(cve_fetcher._parse_nvd_cve_item(invalid_data))

    def test_parse_cve_item_invalid_data_type(self):
        self.assertIsNone(cve_fetcher._parse_nvd_cve_item("not_a_dict")) # type: ignore


class TestFetchCveById(unittest.TestCase):
    """Tests for the fetch_cve_by_id function."""

    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    @patch('zt_immune_system.threat_intel.cve_fetcher._parse_nvd_cve_item')
    def test_fetch_cve_by_id_success(self, mock_parse_item, mock_call_api):
        mock_call_api.return_value = SAMPLE_NVD_API_RESPONSE_SINGLE
        # Create a CVEDetail instance that _parse_nvd_cve_item would return
        mock_parsed_cve = CVEDetail(id="CVE-2023-0001", descriptions=[CVEDescription(lang="en", value="Test")])
        mock_parse_item.return_value = mock_parsed_cve

        result = cve_fetcher.fetch_cve_by_id("CVE-2023-0001")
        self.assertEqual(result, mock_parsed_cve)
        mock_call_api.assert_called_once_with(cve_id="CVE-2023-0001")
        # _parse_nvd_cve_item is called with the 'cve' part of the response
        mock_parse_item.assert_called_once_with(SAMPLE_NVD_API_RESPONSE_SINGLE['vulnerabilities'][0]['cve'])


    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    def test_fetch_cve_by_id_not_found(self, mock_call_api):
        mock_call_api.return_value = SAMPLE_NVD_API_RESPONSE_EMPTY
        result = cve_fetcher.fetch_cve_by_id("CVE-NOT-FOUND")
        self.assertIsNone(result)

    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    def test_fetch_cve_by_id_api_error(self, mock_call_api):
        mock_call_api.return_value = None
        result = cve_fetcher.fetch_cve_by_id("CVE-ERROR-CASE")
        self.assertIsNone(result)

    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    @patch('zt_immune_system.threat_intel.cve_fetcher._parse_nvd_cve_item')
    def test_fetch_cve_by_id_parse_error(self, mock_parse_item, mock_call_api):
        mock_call_api.return_value = SAMPLE_NVD_API_RESPONSE_SINGLE
        mock_parse_item.return_value = None
        result = cve_fetcher.fetch_cve_by_id("CVE-PARSE-ERROR")
        self.assertIsNone(result)

    def test_fetch_cve_by_id_invalid_format(self):
        result = cve_fetcher.fetch_cve_by_id("INVALID-ID-FORMAT") # Does not match CVE_ID_PATTERN
        self.assertIsNone(result) # Expect None due to validation fail


class TestFetchCvesByTimeWindow(unittest.TestCase):
    """Tests for the fetch_cves_by_time_window function."""

    @patch('zt_immune_system.threat_intel.cve_fetcher.time.sleep', return_value=None) # Mock sleep
    @patch('zt_immune_system.threat_intel.cve_fetcher._parse_nvd_cve_item')
    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    def test_fetch_time_window_single_page_success(self, mock_call_api, mock_parse_item, mock_sleep):
        # Simulate API returning one CVE which matches totalResults
        mock_call_api.return_value = SAMPLE_NVD_API_RESPONSE_SINGLE
        mock_parsed_cve_instance = CVEDetail(id="CVE-2023-0001", descriptions=[]) # Simplified for test focus
        mock_parse_item.return_value = mock_parsed_cve_instance

        start_date = "2023-01-01T00:00:00Z"
        end_date = "2023-01-02T00:00:00Z"
        results = cve_fetcher.fetch_cves_by_time_window(start_date, end_date, results_per_page=5)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], mock_parsed_cve_instance)
        expected_params = {'lastModStartDate': start_date, 'lastModEndDate': end_date, 'resultsPerPage': 5, 'startIndex': 0}
        mock_call_api.assert_called_once_with(params=expected_params)
        mock_parse_item.assert_called_once_with(SAMPLE_NVD_API_RESPONSE_SINGLE['vulnerabilities'][0]['cve'])
        mock_sleep.assert_not_called() # No sleep if only one page

    @patch('zt_immune_system.threat_intel.cve_fetcher.time.sleep', return_value=None)
    @patch('zt_immune_system.threat_intel.cve_fetcher._parse_nvd_cve_item')
    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    def test_fetch_time_window_multiple_pages_success(self, mock_call_api, mock_parse_item, mock_sleep):
        # Simulate two pages of results, 1 CVE per page, total 2 CVEs
        response_page1 = {"vulnerabilities": [{"cve": {"id": "CVE-PAGE1-001"}}], "totalResults": 2, "resultsPerPage": 1, "startIndex": 0}
        response_page2 = {"vulnerabilities": [{"cve": {"id": "CVE-PAGE2-001"}}], "totalResults": 2, "resultsPerPage": 1, "startIndex": 1}
        mock_call_api.side_effect = [response_page1, response_page2]

        parsed_cve_page1 = CVEDetail(id="CVE-PAGE1-001", descriptions=[])
        parsed_cve_page2 = CVEDetail(id="CVE-PAGE2-001", descriptions=[])
        mock_parse_item.side_effect = [parsed_cve_page1, parsed_cve_page2]

        start_date = "2023-01-01T00:00:00Z"; end_date = "2023-01-02T00:00:00Z"
        results = cve_fetcher.fetch_cves_by_time_window(start_date, end_date, results_per_page=1)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].id, "CVE-PAGE1-001")
        self.assertEqual(results[1].id, "CVE-PAGE2-001")
        self.assertEqual(mock_call_api.call_count, 2)
        self.assertEqual(mock_parse_item.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1) # Should sleep once between page 1 and page 2 fetches

    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    def test_fetch_time_window_max_results_limit_honored(self, mock_call_api):
        # API reports totalResults = 10, but we request max_total_results = 1
        response_page_data = {"vulnerabilities": [{"cve": {"id": "CVE-001"}}], "totalResults": 10, "resultsPerPage": 1, "startIndex": 0}
        mock_call_api.return_value = response_page_data

        with patch('zt_immune_system.threat_intel.cve_fetcher._parse_nvd_cve_item') as mock_parser:
            mock_parser.return_value = CVEDetail(id="CVE-001", descriptions=[]) # Dummy parsed object
            results = cve_fetcher.fetch_cves_by_time_window("2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z", results_per_page=1, max_total_results=1)

        self.assertEqual(len(results), 1)
        mock_call_api.assert_called_once() # Should stop after the first page due to max_total_results

    def test_fetch_time_window_invalid_date_string_format(self):
        # Pass an invalid date string format
        results = cve_fetcher.fetch_cves_by_time_window("01/01/2023", "2023-01-02T00:00:00Z")
        self.assertEqual(len(results), 0) # Expect empty list due to date parsing error in the function

    @patch('zt_immune_system.threat_intel.cve_fetcher._call_nvd_api')
    def test_fetch_time_window_api_error_on_first_page_call(self, mock_call_api):
        mock_call_api.return_value = None # Simulate API call failure on the first attempt
        results = cve_fetcher.fetch_cves_by_time_window("2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z")
        self.assertEqual(len(results), 0) # Expect empty list


class TestSaveCvesToJson(unittest.TestCase):
    """Tests for the save_cves_to_json function."""

    @patch("builtins.open", new_callable=mock_open) # Mocks the built-in open function
    @patch("zt_immune_system.threat_intel.cve_fetcher.json.dump") # Mocks json.dump
    def test_save_cves_to_json_successful_save(self, mock_json_dump, mock_file_open_instance):
        # Create sample CVEDetail objects
        cve_obj1 = CVEDetail(id="CVE-TEST-001", descriptions=[CVEDescription(lang="en", value="Desc for CVE-001")])
        cve_obj2 = CVEDetail(id="CVE-TEST-002", descriptions=[CVEDescription(lang="en", value="Desc for CVE-002")])
        cves_data_list = [cve_obj1, cve_obj2]
        test_filename = "test_cves_output.json"

        operation_success = cve_fetcher.save_cves_to_json(cves_data_list, test_filename)

        self.assertTrue(operation_success)
        mock_file_open_instance.assert_called_once_with(test_filename, 'w', encoding='utf-8')

        # Verify that json.dump was called with the correct data structure (list of dicts)
        # asdict(cve) is used internally by save_cves_to_json
        expected_data_for_json_dump = [
            {"id": "CVE-TEST-001", "source_identifier": None, "published_date": None, "last_modified_date": None, "vuln_status": None, "descriptions": [{"lang": "en", "value": "Desc for CVE-001"}], "metrics": {}, "weaknesses": [], "references": []},
            {"id": "CVE-TEST-002", "source_identifier": None, "published_date": None, "last_modified_date": None, "vuln_status": None, "descriptions": [{"lang": "en", "value": "Desc for CVE-002"}], "metrics": {}, "weaknesses": [], "references": []}
        ]
        mock_json_dump.assert_called_once_with(expected_data_for_json_dump, mock_file_open_instance(), ensure_ascii=False, indent=4)

    @patch("builtins.open", new_callable=mock_open)
    def test_save_cves_to_json_handles_io_error(self, mock_file_open_instance):
        # Configure the mock_open to raise an IOError when written to
        mock_file_open_instance.side_effect = IOError("Simulated permission denied")
        cves_data_list = [CVEDetail(id="CVE-IO-ERROR", descriptions=[])]
        test_filename = "io_error_test.json"

        operation_success = cve_fetcher.save_cves_to_json(cves_data_list, test_filename)
        self.assertFalse(operation_success) # Expect save to fail

    def test_save_cves_to_json_empty_filename_string(self):
        operation_success = cve_fetcher.save_cves_to_json([], "") # Empty filename
        self.assertFalse(operation_success) # Expect save to fail

    @patch("builtins.open", new_callable=mock_open)
    @patch("zt_immune_system.threat_intel.cve_fetcher.json.dump")
    def test_save_cves_to_json_empty_cve_list(self, mock_json_dump, mock_file_open_instance):
        # Test saving an empty list of CVEs
        operation_success = cve_fetcher.save_cves_to_json([], "empty_cves_list.json")
        self.assertTrue(operation_success) # Should succeed and write an empty JSON array
        mock_json_dump.assert_called_once_with([], mock_file_open_instance(), ensure_ascii=False, indent=4)


if __name__ == '__main__':
    unittest.main()
