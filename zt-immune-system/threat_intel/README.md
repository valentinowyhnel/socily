# Threat Intel Module

This module is responsible for interacting with threat intelligence platforms and fetching/processing threat data.

## MISP Client (`misp_client.py`)

### Configuration

The MISP client requires the following environment variables to be set, or corresponding parameters passed to the constructor:

- `MISP_URL`: The URL of your MISP instance (e.g., https://misp.example.com). Must be HTTPS.
- `MISP_API_KEY`: Your MISP API automation key.

Optional Environment Variables for MISP Client:
- `REQUESTS_CA_BUNDLE`: Path to a CA bundle file for custom SSL certificates if your MISP instance uses a self-signed certificate or a CA not in the default trust store.
- `PYMISP_DEBUG_PROXIES`: HTTP/HTTPS proxy URL (e.g., http://localhost:8080) if you need to route traffic through a proxy for debugging or network reasons.

## CVE Fetcher (`cve_fetcher.py`)

### Purpose

The `cve_fetcher.py` module is designed to fetch CVE (Common Vulnerabilities and Exposures) information from public data sources. Its primary source is the National Vulnerability Database (NVD) via their JSON API 2.0.

### Configuration

-   **NVD API Base URL**: The client uses a default URL for the NVD CVE API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`). This is typically not changed unless the NVD API endpoint changes.
-   **NVD API Key (Optional)**: For higher request rate limits, you can obtain an API key from NVD. If you have one, set it as an environment variable:
    `export NVD_API_KEY="your_nvd_api_key_here"`
    If this variable is not set, the fetcher will still work but will be subject to NVD's public, lower rate limits.

### Features (Planned)
- Fetch CVE details by a specific CVE ID.
- Fetch CVEs based on a time window (e.g., last N days, or a specific date range).
- Return CVE data as structured Python objects (`CVEDetail`).
- Option to save fetched CVEs to a JSON file.
