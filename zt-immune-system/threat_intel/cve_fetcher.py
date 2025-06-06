# CVE Fetcher
#
# This module is responsible for fetching CVE (Common Vulnerabilities and Exposures)
# information from public data sources, primarily the NVD (National Vulnerability Database).
#
# Configuration:
# - NVD_API_BASE_URL: The base URL for the NVD CVE API. Default is provided.
# - NVD_API_KEY: (Optional) An API key for the NVD API to get higher rate limits.
#                If provided, it should be set as an environment variable NVD_API_KEY.
# - REQUEST_TIMEOUT_SECONDS: Timeout for HTTP requests to NVD API.
#
# The client will use the requests library to interact with the NVD API.

import os
import logging
import time
import re
import datetime
import json # For JSON operations
from dataclasses import dataclass, field, asdict # Added asdict
from typing import List, Optional, Dict, Any
import requests

logger = logging.getLogger(__name__)

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 10
MAX_RESULTS_PER_REQUEST_NVD = 2000

CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
NVD_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# Internal helper function to make calls to the NVD API
def _call_nvd_api(cve_id: Optional[str] = None, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
        logger.debug("Using NVD_API_KEY for request.")

    target_url = NVD_API_BASE_URL
    effective_params = params
    if cve_id:
        target_url = f"{NVD_API_BASE_URL}/{cve_id.upper()}"
        effective_params = None

    logger.debug(f"Calling NVD API. URL: {target_url}, Params: {effective_params}")

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                target_url,
                headers=headers,
                params=effective_params,
                timeout=REQUEST_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error calling NVD API ({target_url}): {e.response.status_code} - {e.response.text}")
            if e.response.status_code == 403:
                if NVD_API_KEY:
                    logger.error("NVD API Key might be invalid, expired, or over quota. Will not retry.")
                    return None
                if attempt < MAX_RETRIES - 1:
                    actual_retry_delay = RETRY_DELAY_SECONDS * (2 ** attempt)
                    logger.warning(f"Rate limited by NVD API (attempt {attempt + 1}/{MAX_RETRIES}). Retrying in {actual_retry_delay} seconds...")
                    time.sleep(actual_retry_delay)
                    continue
                else:
                    logger.error("Max retries reached for rate limiting. Aborting.")
                    return None
            elif e.response.status_code == 404:
                logger.warning(f"Resource not found (404) at NVD API for URL: {target_url}, Params: {effective_params}")
                return None
            else:
                logger.error(f"Unhandled HTTP error {e.response.status_code}. Aborting.")
                return None
        except requests.exceptions.Timeout:
            logger.error(f"Request to NVD API timed out ({target_url}, attempt {attempt + 1}/{MAX_RETRIES}).")
            if attempt < MAX_RETRIES - 1:
                actual_retry_delay = (RETRY_DELAY_SECONDS / 2) * (2 ** attempt)
                logger.info(f"Retrying due to timeout in {actual_retry_delay} seconds...")
                time.sleep(actual_retry_delay)
                continue
            else:
                logger.error("Max retries reached for timeout. Aborting.")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"A general request error occurred when calling NVD API ({target_url}, attempt {attempt + 1}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES - 1:
                actual_retry_delay = (RETRY_DELAY_SECONDS / 2) * (2 ** attempt)
                logger.info(f"Retrying due to general request error in {actual_retry_delay} seconds...")
                time.sleep(actual_retry_delay)
                continue
            else:
                logger.error("Max retries reached for general request exception. Aborting.")
                return None
        except ValueError as e:
            response_text = response.text if 'response' in locals() and hasattr(response, 'text') else "N/A"
            logger.error(f"Failed to decode JSON response from NVD API ({target_url}): {e}. Response text: {response_text[:500]}...")
            return None
    logger.error(f"All {MAX_RETRIES} retries failed for NVD API call to {target_url} with params: {effective_params}.")
    return None


@dataclass
class CVSSMetric:
    """Represents a CVSS metric (v2 or v3.x)."""
    source: str
    cvss_type: str
    version: str
    vector_string: str
    base_score: float
    base_severity: str
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

@dataclass
class CVEProblemType:
    """Represents a CWE ID associated with a CVE."""
    cwe_id: str
    description: str

@dataclass
class CVEReference:
    """Represents a reference URL for a CVE."""
    url: str
    source: str
    tags: Optional[List[str]] = field(default_factory=list)

@dataclass
class CVEDescription:
    """Represents a description for a CVE, typically in English."""
    lang: str
    value: str

@dataclass
class CVEDetail:
    """
    A structured representation of a CVE's details fetched from NVD.
    """
    id: str
    source_identifier: Optional[str] = None
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    vuln_status: Optional[str] = None
    descriptions: List[CVEDescription] = field(default_factory=list)
    metrics: Dict[str, List[CVSSMetric]] = field(default_factory=dict)
    weaknesses: List[CVEProblemType] = field(default_factory=list)
    references: List[CVEReference] = field(default_factory=list)

    def get_english_description(self) -> Optional[str]:
        """Helper to get the English description if available."""
        for desc in self.descriptions:
            if desc.lang.lower() == "en":
                return desc.value
        return None

    def get_cvss_v3_metric(self) -> Optional[CVSSMetric]:
        """
        Helper to get the primary CVSSv3.x metric.
        Prefers CVSS v3.1, then v3.0. Looks for 'Primary' type first.
        """
        for version_key in ["cvssMetricV31", "cvssMetricV30"]:
            if version_key in self.metrics and self.metrics[version_key]:
                metrics_list = self.metrics[version_key]
                for metric in metrics_list:
                    if hasattr(metric, 'cvss_type') and metric.cvss_type and metric.cvss_type.lower() == "primary":
                        return metric
                if metrics_list:
                    return metrics_list[0]
        return None

def _parse_nvd_cve_item(cve_data: Dict[str, Any]) -> Optional[CVEDetail]:
    """
    Parses a single CVE item from the NVD API 2.0 response structure
    into a CVEDetail dataclass object.
    """
    if not isinstance(cve_data, dict):
        logger.error(f"Invalid cve_data provided to parser: expected dict, got {type(cve_data)}")
        return None
    try:
        cve_id = cve_data['id']
        parsed_descriptions = []
        for desc_data in cve_data.get('descriptions', []):
            if isinstance(desc_data, dict) and 'lang' in desc_data and 'value' in desc_data:
                parsed_descriptions.append(CVEDescription(lang=desc_data['lang'], value=desc_data['value']))

        parsed_metrics: Dict[str, List[CVSSMetric]] = {}
        raw_metrics_dict = cve_data.get('metrics', {})
        if isinstance(raw_metrics_dict, dict):
            for metric_key, metric_list_data in raw_metrics_dict.items():
                if isinstance(metric_list_data, list):
                    current_key_metrics = []
                    for metric_data_item in metric_list_data:
                        if not isinstance(metric_data_item, dict): continue
                        cvss_data = metric_data_item.get('cvssData', {})
                        if not isinstance(cvss_data, dict): continue
                        if all(k in cvss_data for k in ['version', 'vectorString', 'baseScore']) and 'source' in metric_data_item:
                            severity = cvss_data.get('baseSeverity')
                            if not severity and metric_data_item.get('baseSeverity'):
                                severity = metric_data_item['baseSeverity']
                            if not severity: severity = "UNKNOWN"
                            current_key_metrics.append(CVSSMetric(
                                source=metric_data_item['source'],
                                cvss_type=metric_data_item.get('type', 'Unknown'),
                                version=str(cvss_data['version']),
                                vector_string=cvss_data['vectorString'],
                                base_score=float(cvss_data['baseScore']),
                                base_severity=severity.upper(),
                                exploitability_score=cvss_data.get('exploitabilityScore'),
                                impact_score=cvss_data.get('impactScore')
                            ))
                    if current_key_metrics:
                        parsed_metrics[metric_key] = current_key_metrics

        parsed_weaknesses = []
        for weakness_entry in cve_data.get('weaknesses', []):
            if not isinstance(weakness_entry, dict): continue
            for desc_item in weakness_entry.get('description', []):
                if isinstance(desc_item, dict) and desc_item.get('lang', '').lower() == 'en' and 'value' in desc_item:
                    cwe_value = desc_item['value']
                    if cwe_value and (cwe_value.upper().startswith("CWE-") or "NVD-CWE" in cwe_value.upper()):
                         parsed_weaknesses.append(CVEProblemType(
                             cwe_id=cwe_value.upper(),
                             description=weakness_entry.get('type', '')
                        ))

        parsed_references = []
        for ref_data in cve_data.get('references', []):
            if isinstance(ref_data, dict) and 'url' in ref_data and 'source' in ref_data:
                parsed_references.append(CVEReference(
                    url=ref_data['url'],
                    source=ref_data['source'],
                    tags=ref_data.get('tags', [])
                ))

        return CVEDetail(
            id=cve_id,
            source_identifier=cve_data.get('sourceIdentifier'),
            published_date=cve_data.get('published'),
            last_modified_date=cve_data.get('lastModified'),
            vuln_status=cve_data.get('vulnStatus'),
            descriptions=parsed_descriptions,
            metrics=parsed_metrics,
            weaknesses=parsed_weaknesses,
            references=parsed_references
        )
    except KeyError as e:
        logger.error(f"KeyError while parsing CVE data for {cve_data.get('id', 'Unknown CVE')}: Missing key {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error while parsing CVE data for {cve_data.get('id', 'Unknown CVE')}: {e}", exc_info=True)
        return None

def fetch_cve_by_id(cve_id: str) -> Optional[CVEDetail]:
    """
    Fetches a single CVE from the NVD API by its ID.
    """
    if not isinstance(cve_id, str) or not CVE_ID_PATTERN.match(cve_id):
        logger.error(f"Invalid CVE ID format: '{cve_id}'. Must match pattern '{CVE_ID_PATTERN.pattern}'.")
        return None
    effective_cve_id = cve_id.upper()
    logger.info(f"Fetching CVE details for ID: {effective_cve_id}")
    api_response = _call_nvd_api(cve_id=effective_cve_id)
    if not api_response:
        logger.warning(f"No response or error from NVD API for CVE ID: {effective_cve_id}")
        return None
    vulnerabilities = api_response.get('vulnerabilities')
    if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
        if len(vulnerabilities) > 1:
            logger.warning(f"Expected 1 vulnerability for CVE ID {effective_cve_id}, but received {len(vulnerabilities)}. Using the first one.")
        cve_item_data = vulnerabilities[0].get('cve')
        if cve_item_data and isinstance(cve_item_data, dict):
            parsed_cve = _parse_nvd_cve_item(cve_item_data)
            if parsed_cve:
                logger.info(f"Successfully fetched and parsed CVE: {parsed_cve.id}")
                return parsed_cve
            else:
                logger.error(f"Failed to parse CVE data from NVD response for {effective_cve_id}.")
                return None
        else:
            logger.warning(f"No 'cve' data dictionary found in NVD response item for {effective_cve_id}. Response item: {vulnerabilities[0]}")
            return None
    else:
        logger.warning(f"No 'vulnerabilities' list found or list is empty in NVD API response for {effective_cve_id}. API Response: {str(api_response)[:500]}...")
        return None

def fetch_cves_by_time_window(
    start_date_str: str,
    end_date_str: str,
    search_modified: bool = True,
    results_per_page: int = 100,
    max_total_results: Optional[int] = None
) -> List[CVEDetail]:
    """
    Fetches CVEs from NVD API 2.0 based on a time window (last modified or published).
    (Docstring remains similar, code is the same as previous step)
    """
    all_fetched_cves: List[CVEDetail] = []
    current_start_index = 0

    if not isinstance(start_date_str, str) or not isinstance(end_date_str, str):
        logger.error("start_date_str and end_date_str must be strings.")
        return []
    try:
        datetime.datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
        datetime.datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
    except ValueError as e:
        logger.error(f"Invalid date format for start_date_str or end_date_str: {e}. Use ISO 8601 format (e.g., YYYY-MM-DDTHH:MM:SSZ).")
        return []

    if not (0 < results_per_page <= MAX_RESULTS_PER_REQUEST_NVD):
        logger.warning(f"results_per_page ({results_per_page}) is outside NVD's allowed range (1-{MAX_RESULTS_PER_REQUEST_NVD}). Clamping to {MAX_RESULTS_PER_REQUEST_NVD}.")
        results_per_page = MAX_RESULTS_PER_REQUEST_NVD

    date_param_prefix = "lastMod" if search_modified else "pub"
    base_query_params = {
        f"{date_param_prefix}StartDate": start_date_str,
        f"{date_param_prefix}EndDate": end_date_str,
        "resultsPerPage": results_per_page
    }

    logger.info(f"Initiating fetch for CVEs from {start_date_str} to {end_date_str} (search_modified={search_modified}).")

    while True:
        paginated_params = base_query_params.copy()
        paginated_params["startIndex"] = current_start_index

        logger.debug(f"Fetching page with startIndex: {current_start_index}, resultsPerPage: {results_per_page}")
        api_response = _call_nvd_api(params=paginated_params)

        if not api_response:
            logger.error(f"Failed to retrieve data from NVD API for startIndex {current_start_index}. Terminating fetch for this window.")
            break

        total_results_reported_by_api = api_response.get('totalResults', 0)
        vulnerabilities_on_page = api_response.get('vulnerabilities', [])

        if not vulnerabilities_on_page:
            if current_start_index == 0:
                 logger.info(f"No CVEs found in NVD for the specified time window and criteria. Total results reported by API: {total_results_reported_by_api}")
            else:
                logger.info(f"No more CVEs found on page with startIndex {current_start_index}. Total CVEs fetched: {len(all_fetched_cves)}.")
            break

        for cve_item_wrapper in vulnerabilities_on_page:
            cve_item_data = cve_item_wrapper.get('cve')
            if cve_item_data and isinstance(cve_item_data, dict):
                parsed_cve = _parse_nvd_cve_item(cve_item_data)
                if parsed_cve:
                    all_fetched_cves.append(parsed_cve)
                else:
                    logger.warning(f"Could not parse a CVE item from page with startIndex {current_start_index}. CVE ID in item: {cve_item_data.get('id', 'Unknown')}")
            else:
                logger.warning(f"CVE item wrapper missing 'cve' key or 'cve' data is not a dict, on page with startIndex {current_start_index}. Item: {str(cve_item_wrapper)[:200]}...")

        logger.info(f"Fetched {len(vulnerabilities_on_page)} CVEs on this page. Total fetched so far: {len(all_fetched_cves)} out of {total_results_reported_by_api} reported by API for this query.")

        if max_total_results is not None and len(all_fetched_cves) >= max_total_results:
            logger.info(f"Reached specified max_total_results limit of {max_total_results}. Stopping fetch.")
            return all_fetched_cves[:max_total_results]

        current_start_index += results_per_page

        if current_start_index >= total_results_reported_by_api:
            logger.info(f"All {total_results_reported_by_api} CVEs fetched for the current query parameters and time window.")
            break

        if not vulnerabilities_on_page:
            logger.warning("Received an empty vulnerabilities list unexpectedly, terminating pagination.")
            break

        delay = RETRY_DELAY_SECONDS if not NVD_API_KEY else (RETRY_DELAY_SECONDS / 5)
        logger.debug(f"Pausing for {delay:.1f} seconds before fetching next page...")
        time.sleep(delay)

    logger.info(f"Completed fetching CVEs for time window. Total CVEDetail objects created: {len(all_fetched_cves)}")
    return all_fetched_cves

# --- New Function: save_cves_to_json ---
def save_cves_to_json(cves: List[CVEDetail], filename: str) -> bool:
    """
    Saves a list of CVEDetail objects to a JSON file.

    Each CVEDetail object is converted to a dictionary using `dataclasses.asdict`
    before serialization to ensure all nested dataclasses are also converted.

    :param cves: A list of CVEDetail objects to save.
    :type cves: List[CVEDetail]
    :param filename: The name of the file (including path) to save the JSON data to.
                     The directory for the file must already exist.
    :type filename: str
    :return: True if saving was successful, False otherwise.
    :rtype: bool
    """
    if not filename: # Basic check for empty filename string
        logger.error("Filename cannot be empty for saving CVEs to JSON.")
        return False
    if not isinstance(cves, list): # Ensure 'cves' is a list
        logger.error("Input 'cves' must be a list of CVEDetail objects.")
        return False

    logger.info(f"Attempting to save {len(cves)} CVEs to JSON file: {filename}")
    try:
        # Convert list of CVEDetail dataclass instances to list of dicts
        # This is crucial for json.dump to work correctly with nested dataclasses.
        cves_as_dicts = [asdict(cve) for cve in cves]

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(cves_as_dicts, f, ensure_ascii=False, indent=4)

        logger.info(f"Successfully saved {len(cves)} CVEs to {filename}")
        return True
    except TypeError as e: # Error during asdict conversion or json.dump if objects are not serializable
        logger.error(f"TypeError during JSON serialization for {filename}: {e}. Ensure all objects are serializable.", exc_info=True)
        return False
    except IOError as e: # File system errors (e.g., permission denied, disk full)
        logger.error(f"IOError saving CVEs to {filename}: {e}", exc_info=True)
        return False
    except Exception as e: # Catch any other unexpected errors during the save process
        logger.error(f"Unexpected error saving CVEs to {filename}: {e}", exc_info=True)
        return False


# Example usage (for testing save_cves_to_json)
if __name__ == '__main__':
    if not logging.getLogger(__name__).hasHandlers():
        logging.basicConfig(level=logging.DEBUG) # Set to DEBUG for dev testing

    # --- Previous __main__ content for NVD_API_KEY logging, fetch_cve_by_id, fetch_cves_by_time_window tests ---
    logger.info("CVE Fetcher module loaded for comprehensive testing.")
    if NVD_API_KEY:
        key_display = f"...{NVD_API_KEY[-4:]}" if len(NVD_API_KEY) >=4 else " (key too short)"
        logger.info(f"NVD_API_KEY is configured (ending with: {key_display})")
    else:
        logger.warning("NVD_API_KEY is not configured. Using public NVD API rate limits.")

    # Test fetch_cve_by_id
    test_cve_id_main = os.getenv("TEST_CVE_ID", "CVE-2023-38545")
    logger.info(f"\n--- Testing fetch_cve_by_id with {test_cve_id_main} ---")
    fetched_cve_single = fetch_cve_by_id(test_cve_id_main)
    # (Log output for fetch_cve_by_id can be kept from previous step if desired for verbosity)

    # Test fetch_cves_by_time_window
    logger.info(f"\n--- Testing fetch_cves_by_time_window ---")
    try:
        end_date_dt_obj = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
        start_date_dt_obj = end_date_dt_obj - datetime.timedelta(days=1)
        test_end_date_str_main = end_date_dt_obj.strftime(NVD_DATETIME_FORMAT)
        test_start_date_str_main = start_date_dt_obj.strftime(NVD_DATETIME_FORMAT)
        logger.info(f"Time window for fetch_cves_by_time_window test: {test_start_date_str_main} to {test_end_date_str_main}")
        cves_fetched_in_window = fetch_cves_by_time_window(
            start_date_str=test_start_date_str_main, end_date_str=test_end_date_str_main,
            results_per_page=5, max_total_results=2 # Small numbers for quick test
        )
        if cves_fetched_in_window:
            logger.info(f"fetch_cves_by_time_window returned {len(cves_fetched_in_window)} CVEs.")
        else:
            logger.info("fetch_cves_by_time_window returned no CVEs for the test window.")
    except Exception as e_main_fetch:
        logger.error(f"Error during fetch_cves_by_time_window test in __main__: {e_main_fetch}", exc_info=True)

    # --- Test save_cves_to_json ---
    logger.info(f"\n--- Testing save_cves_to_json ---")
    # Create a few sample CVEDetail objects for testing the save function
    sample_cve1_desc = CVEDescription(lang="en", value="Description for sample CVE-TEST-001. This is a test vulnerability.")
    sample_cve1_metric_v3 = CVSSMetric(source="test@organization.org", cvss_type="Primary", version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", base_score=6.5, base_severity="MEDIUM")
    sample_cve1_ref = CVEReference(url="http://example.com/ref/001", source="example.com", tags=["Technical Description"])
    sample_cve1_weakness = CVEProblemType(cwe_id="CWE-120", description="Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')")
    sample_cve1 = CVEDetail(
        id="CVE-TEST-001",
        descriptions=[sample_cve1_desc],
        metrics={"cvssMetricV31": [sample_cve1_metric_v3]},
        published_date="2023-01-01T00:00:00Z",
        last_modified_date="2023-01-02T12:00:00Z",
        vuln_status="Analyzed",
        references=[sample_cve1_ref],
        weaknesses=[sample_cve1_weakness]
    )

    sample_cve2_desc = CVEDescription(lang="en", value="Another sample CVE, CVE-TEST-002, with fewer details.")
    sample_cve2 = CVEDetail(id="CVE-TEST-002", descriptions=[sample_cve2_desc], published_date="2023-01-02T00:00:00Z")

    test_cves_list_for_save = [sample_cve1, sample_cve2]
    test_json_filename = "test_cves_output.json" # Will be created in the current working directory

    if save_cves_to_json(test_cves_list_for_save, test_json_filename):
        logger.info(f"save_cves_to_json test successful. File '{test_json_filename}' should be created/overwritten.")
        # Verification step (optional, but good for automated tests)
        try:
            with open(test_json_filename, 'r', encoding='utf-8') as f_check:
                data_read_from_file = json.load(f_check)
                if len(data_read_from_file) == 2 and data_read_from_file[0]['id'] == "CVE-TEST-001":
                    logger.info(f"File '{test_json_filename}' content basic verification successful.")
                else:
                    logger.error(f"File '{test_json_filename}' content verification failed. Data: {data_read_from_file}")
            # os.remove(test_json_filename) # Clean up the test file after verification
            # logger.info(f"Cleaned up test file: {test_json_filename}")
        except Exception as e_read_verify:
            logger.error(f"Error during test file verification or cleanup: {e_read_verify}", exc_info=True)

    else:
        logger.error(f"save_cves_to_json test failed for filename '{test_json_filename}'.")

    # Test saving an empty list
    logger.info(f"\n--- Testing save_cves_to_json with an empty list ---")
    empty_list_filename = "empty_cves_output.json"
    if save_cves_to_json([], empty_list_filename):
        logger.info(f"save_cves_to_json with empty list test successful. File '{empty_list_filename}' created.")
        # os.remove(empty_list_filename) # Clean up
    else:
        logger.error(f"save_cves_to_json with empty list test failed for '{empty_list_filename}'.")

    logger.info("\n--- All CVE Fetcher __main__ tests completed ---")
