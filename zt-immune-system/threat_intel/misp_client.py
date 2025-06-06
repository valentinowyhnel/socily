# MISP Client
#
# This client interacts with a MISP instance to fetch and submit threat intelligence data.
# It uses the PyMISP library for communication with the MISP API.
#
# Configuration:
# The client requires the following environment variables to be set, or corresponding
# parameters passed to the constructor:
# - MISP_URL: The URL of your MISP instance (e.g., https://misp.example.com). Must be HTTPS.
# - MISP_API_KEY: Your MISP API automation key.
#
# Optional Environment Variables:
# - REQUESTS_CA_BUNDLE: Path to a CA bundle file for custom SSL certificates if your MISP
#   instance uses a self-signed certificate or a CA not in the default trust store.
# - PYMISP_DEBUG_PROXIES: HTTP/HTTPS proxy URL (e.g., http://localhost:8080) if you need
#   to route traffic through a proxy for debugging or network reasons.
#
# Logging:
# The client uses Python's standard `logging` module. The logger is named
# 'zt_immune_system.threat_intel.misp_client' (if file is in that path).
# You can configure this logger in your application to control log output and formatting.
# For example:
#   import logging
#   logging.getLogger('zt_immune_system.threat_intel.misp_client').setLevel(logging.DEBUG)
#
# Example Usage (basic connection):
#   from zt_immune_system.threat_intel.misp_client import MISPClient
#   try:
#       client = MISPClient(misp_url="https://your.misp.instance", misp_api_key="YOUR_API_KEY")
#       # Use the client...
#       events = client.search_events(tags=["tlp:green"], limit=5)
#       if events:
#           for event in events:
#               print(f"Event ID: {event['id']}, Info: {event['info']}")
#   except Exception as e:
#       print(f"An error occurred: {e}")

import os
import warnings
import logging
from typing import Optional, List, Dict, Tuple, Any, Union
from io import BytesIO

from pymisp import PyMISP, MISPError, MISPAPIError

# Valid MISP attribute types (not exhaustive, but a good start for validation)
# This list can be expanded or loaded from MISP itself if needed for stricter validation.
VALID_MISP_ATTRIBUTE_TYPES: List[str] = [
    "autonomous-system", "snort", "x509-fingerprint-sha1", "x509-fingerprint-md5",
    "ja3-fingerprint-md5", "jarm-fingerprint", "hassh-md5", "hasshserver-md5",
    "filename", "domain", "domain|ip", "ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
    "md5", "sha1", "sha256", "sha512", "ssdeep", "tlsh", "pehash",
    "url", "user-agent", "regkey", "regkey|value", "mutex", "hostname", "email-src",
    "email-dst", "email-subject", "email-attachment", "threat-actor", "vulnerability",
    "malware-sample", "comment", "text", "pattern-in-file", "pattern-in-traffic",
    "pattern-in-memory", "yara", "sigma", "misp-galaxy"
    # Add more as commonly used/needed
]

# Module-level logger. The name will be based on the file's path and name.
logger = logging.getLogger(__name__)

class MISPClient:
    """
    A client for interacting with a MISP (Malware Information Sharing Platform) instance.

    This client provides methods for common MISP operations such as fetching events,
    searching for events and attributes, adding attributes and sightings, and
    downloading malware samples. It handles connection setup, authentication,
    and basic error handling, utilizing Python's standard logging module.
    """

    def __init__(self, misp_url: Optional[str] = None, misp_api_key: Optional[str] = None, proxies: Optional[Dict[str, str]] = None):
        """
        Initializes the MISPClient.

        Reads MISP_URL and MISP_API_KEY from environment variables if not provided as arguments.
        Ensures MISP_URL is HTTPS for security. Establishes and verifies the connection
        to the MISP instance using PyMISP.

        :param misp_url: URL of the MISP instance (e.g., "https://misp.example.com").
                         Overrides the MISP_URL environment variable if provided.
        :type misp_url: str, optional
        :param misp_api_key: API key for authentication with the MISP instance.
                             Overrides the MISP_API_KEY environment variable if provided.
        :type misp_api_key: str, optional
        :param proxies: A dictionary of proxies to use for requests (e.g., {'http': '...', 'https': '...'}).
                        Overrides PYMISP_DEBUG_PROXIES environment variable if provided.
        :type proxies: dict, optional
        :raises ValueError: If MISP_URL or MISP_API_KEY is not provided or found in environment.
        :raises MISPError: If there's an issue connecting to MISP (e.g., authentication failure, network error).
        :raises ConnectionError: If an unexpected error occurs during PyMISP initialization.
        """
        self.misp_url = misp_url or os.getenv("MISP_URL")
        self.misp_api_key = misp_api_key or os.getenv("MISP_API_KEY")

        effective_proxies = proxies # Use provided proxies first
        if not effective_proxies: # If not provided, check environment variable
            proxy_env_val = os.getenv("PYMISP_DEBUG_PROXIES")
            if proxy_env_val:
                effective_proxies = {'http': proxy_env_val, 'https': proxy_env_val}
                logger.info(f"Using proxies from PYMISP_DEBUG_PROXIES environment variable: {effective_proxies}")

        if not self.misp_url or not self.misp_api_key:
            logger.critical("MISP_URL and MISP_API_KEY must be provided either as arguments or environment variables.")
            raise ValueError("MISP_URL and MISP_API_KEY must be provided.")

        if not self.misp_url.startswith("https://"):
            logger.warning(f"MISP_URL '{self.misp_url}' does not start with https. This is insecure and may not function as expected with SSL verification.")
            warnings.warn(f"MISP_URL '{self.misp_url}' should use HTTPS for secure communication.", UserWarning)
            # PyMISP might default ssl to False here; explicit handling below.

        try:
            use_ssl = self.misp_url.startswith("https://")
            # debug=False for production use; PyMISP can be very verbose.
            self.misp = PyMISP(self.misp_url, self.misp_api_key, ssl=use_ssl, proxies=effective_proxies, debug=False)

            # Verify connection and get server version for logging.
            server_settings = self.misp.get_server_settings()
            if server_settings and isinstance(server_settings, dict) and \
               'server' in server_settings and isinstance(server_settings['server'], dict) and \
               'version' in server_settings['server']:
                 misp_version = server_settings['server']['version']
                 logger.info(f"Successfully connected to MISP instance at {self.misp_url} (Version: {misp_version}, SSL: {use_ssl})")
            else:
                 # Fallback if version info is not in the expected place. Connection might still be okay.
                 logger.info(f"Successfully connected to MISP instance at {self.misp_url} (SSL: {use_ssl}). Version check response structure unexpected: {server_settings}")

        except MISPAPIError as e: # Typically authentication or API specific errors from PyMISP
            logger.error(f"MISP API Error during initialization for {self.misp_url}: {e}", exc_info=True)
            raise
        except MISPError as e: # Broader PyMISP errors, including some connection issues
            logger.error(f"Failed to connect to MISP instance at {self.misp_url}. Error: {e}", exc_info=True)
            raise
        except Exception as e: # Catch-all for other unexpected errors during setup (e.g., network issues not caught by PyMISP)
            logger.error(f"An unexpected error occurred while connecting to MISP at {self.misp_url}: {e}", exc_info=True)
            raise ConnectionError(f"An unexpected error occurred while connecting to MISP: {e}")


    def _validate_attribute_type(self, type_attribute: str) -> bool:
        """
        Validates if the attribute type is in a predefined list of known MISP types.
        Logs a warning if the type is not found. This method is for guidance and
        does not currently prevent usage of unknown types, as MISP instances can have custom types.

        :param type_attribute: The MISP attribute type string (e.g., "ip-dst", "md5").
        :type type_attribute: str
        :return: True (currently always, as it only warns).
        :rtype: bool
        """
        if type_attribute not in VALID_MISP_ATTRIBUTE_TYPES:
            logger.warning(f"Attribute type '{type_attribute}' is not in the client's predefined list of valid types. It might be a custom type or a typo. Consult MISP documentation for standard types.")
        return True

    def get_event(self, event_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """
        Fetches a specific event by its ID from the MISP instance.

        :param event_id: The ID of the event to fetch. Can be a string or an integer.
        :type event_id: str or int
        :return: A dictionary containing the event details if found, otherwise None.
                 The structure of the dictionary matches the MISP event JSON structure.
        :rtype: dict, optional
        """
        if not isinstance(event_id, (str, int)):
            logger.error(f"Invalid event_id type: {type(event_id)}. Must be string or integer.")
            return None

        event_id_str = str(event_id) # PyMISP expects string for event ID
        logger.debug(f"Attempting to fetch event with ID: {event_id_str}")
        try:
            event_data = self.misp.get_event(event_id_str) # PyMISP returns a dict

            # Check for successful response: 'Event' key present
            if event_data and 'Event' in event_data:
                # Truncate long info fields for brevity in logs
                event_info = event_data['Event'].get('info', 'N/A')
                logger.info(f"Successfully fetched event ID: {event_id_str}, Info: {event_info[:100]}{'...' if len(event_info)>100 else ''}")
                return event_data['Event']

            # Handle common "not found" or error scenarios
            if event_data and 'errors' in event_data: # Explicit error message from MISP
                # MISP often returns errors as a list: [status_code, message_dict]
                if isinstance(event_data['errors'], (list, tuple)) and len(event_data['errors']) > 0 and event_data['errors'][0] == 404:
                    logger.warning(f"Event with ID {event_id_str} not found (404).")
                else:
                    logger.error(f"API error reported by MISP while fetching event {event_id_str}: {event_data.get('errors')}")
                return None
            if not event_data: # Empty dict {} can also mean "not found" in some PyMISP versions or scenarios
                 logger.warning(f"Event with ID {event_id_str} not found (empty response from PyMISP).")
                 return None

            # If the response is unexpected (e.g., not an error, but no 'Event' key)
            logger.warning(f"Unexpected response structure when fetching event {event_id_str}. Response: {event_data}")
            return None
        except MISPAPIError as e: # Errors raised by PyMISP itself (e.g., connection issues, auth)
            logger.error(f"PyMISP API error while fetching event {event_id_str}: {e}", exc_info=True)
            return None
        except Exception as e: # Catch any other unexpected errors during the process
            logger.error(f"Unexpected error while fetching event {event_id_str}: {e}", exc_info=True)
            return None

    def search_events(self, controller: str = 'attributes', value: Optional[str] = None,
                      type_attribute: Optional[str] = None, tags: Optional[List[str]] = None,
                      date_from: Optional[str] = None, date_to: Optional[str] = None,
                      limit: Optional[int] = None, page: Optional[int] = None,
                      **kwargs: Any) -> List[Dict[str, Any]]:
        """
        Searches for events in MISP based on various criteria.

        This method can search by attributes, event metadata, tags, dates, etc.
        The `controller` parameter determines the main search endpoint (e.g., 'attributes', 'events').

        :param controller: The MISP search controller to use (e.g., 'attributes', 'events', 'objects').
                           Defaults to 'attributes'.
        :type controller: str
        :param value: The value to search for (e.g., an IP address, domain name, hash).
                      Used when searching by attributes or other value-based criteria.
        :type value: str, optional
        :param type_attribute: The type of attribute to search for (e.g., 'ip-dst', 'domain', 'md5').
                               Used with `value` when searching attributes.
        :type type_attribute: str, optional
        :param tags: A list of tags to filter events by. Tags are OR'ed by default unless prefixed
                     (e.g., `["tagA", "!tagB"]`).
        :type tags: list of str, optional
        :param date_from: Start date for the search range (YYYY-MM-DD).
        :type date_from: str, optional
        :param date_to: End date for the search range (YYYY-MM-DD).
        :type date_to: str, optional
        :param limit: Limit the number of results returned by MISP.
        :type limit: int, optional
        :param page: Page number for paginated results from MISP.
        :type page: int, optional
        :param kwargs: Additional keyword arguments to pass directly to PyMISP's search method
                       (e.g., `eventid`, `org`, `searchall`, `published`, `eventinfo`).
                       Consult PyMISP documentation for all available search parameters.
        :return: A list of dictionaries, where each dictionary is a MISP event.
                 Returns an empty list if no events are found or an error occurs.
        :rtype: list of dict
        """
        search_params = kwargs # Start with any additional parameters passed via kwargs

        # Populate search parameters from named arguments, performing basic validation
        if value is not None:
            if not isinstance(value, str):
                logger.error("Search parameter 'value' must be a string.")
                return []
            search_params['value'] = value
        if type_attribute:
            if not isinstance(type_attribute, str):
                logger.error("Search parameter 'type_attribute' must be a string.")
                return []
            self._validate_attribute_type(type_attribute) # Warn if type is unknown
            search_params['type'] = type_attribute
        if tags: # PyMISP expects tags as a list or comma-separated string
            if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags):
                search_params['tags'] = tags
            elif isinstance(tags, str): # Allow pre-formatted comma-separated string
                 search_params['tags'] = tags # PyMISP handles splitting if needed for some endpoints
            else:
                logger.error("Search parameter 'tags' must be a list of strings or a comma-separated string.")
                return []

        # Add other specific parameters if they exist
        if date_from: search_params['date_from'] = date_from
        if date_to: search_params['date_to'] = date_to
        if limit is not None: search_params['limit'] = limit # Allow 0 if MISP API supports it for "no limit"
        if page is not None: search_params['page'] = page

        logger.debug(f"Searching MISP (controller: '{controller}') with parameters: {search_params}")
        try:
            # PyMISP's search method typically returns a list of dictionaries.
            # Each dictionary can be a MISPEvent or MISPAttribute object-like dict.
            raw_results = self.misp.search(controller=controller, **search_params)

            processed_events: List[Dict[str, Any]] = []
            if not raw_results: # Empty list or None indicates no results
                logger.info(f"Search (controller: '{controller}', params: {search_params}) returned no results.")
                return []

            # Response structure from PyMISP can sometimes be nested under a 'response' key
            # This normalization step was removed based on typical direct list returns from `misp.search`
            # If issues arise, one might need to check `if isinstance(raw_results, dict) and 'response' in raw_results: raw_results = raw_results['response']`

            if controller == 'events':
                # Expects a list of event dicts, each containing an 'Event' key.
                for res_item in raw_results:
                    if isinstance(res_item, dict) and 'Event' in res_item:
                        processed_events.append(res_item['Event'])
                    else:
                        logger.warning(f"Unexpected item structure in 'events' search result: {res_item}")
            elif controller == 'attributes':
                # Expects a list of attribute dicts. We need to fetch their parent events.
                event_ids = set() # Use a set to store unique event IDs
                for attr_item in raw_results:
                    # Attributes might be directly in the list or nested under 'Attribute' key
                    actual_attr = attr_item.get('Attribute', attr_item) if isinstance(attr_item, dict) else {}
                    if isinstance(actual_attr, dict) and 'event_id' in actual_attr:
                        event_ids.add(actual_attr['event_id'])
                    else:
                        logger.warning(f"Unexpected item structure or missing 'event_id' in 'attributes' search result item: {attr_item}")

                if event_ids:
                    logger.debug(f"Found {len(event_ids)} unique event IDs from attribute search. Fetching full event details...")
                    for eid in event_ids:
                        event_detail = self.get_event(eid) # get_event handles its own logging
                        if event_detail:
                            processed_events.append(event_detail)
            else:
                # For other controllers, the structure might vary.
                # Log and return raw results if specific handling isn't implemented.
                logger.info(f"Search for controller '{controller}' returned {len(raw_results)} items. Returning raw results as is, as specific processing for this controller is not implemented.")
                return raw_results # Type compatibility might be an issue here if not list of dicts.

            logger.info(f"Search (controller: '{controller}', params: {search_params}) found {len(processed_events)} processed events.")
            return processed_events

        except MISPAPIError as e:
            logger.error(f"PyMISP API error during search (controller: '{controller}', params: {search_params}): {e}", exc_info=True)
            return []
        except Exception as e:
            logger.error(f"Unexpected error during search (controller: '{controller}', params: {search_params}): {e}", exc_info=True)
            return []

    def add_attribute(self, event_id: Union[str, int], value: str, type_attribute: str,
                      category: Optional[str] = None, comment: Optional[str] = None,
                      to_ids: Optional[bool] = None, distribution: Optional[int] = None,
                      **kwargs: Any) -> Optional[Dict[str, Any]]:
        """
        Adds an attribute to a specific event in MISP.

        :param event_id: The ID of the event to add the attribute to.
        :type event_id: str or int
        :param value: The value of the attribute (e.g., "1.2.3.4", "evil.com").
        :type value: str
        :param type_attribute: The MISP type of the attribute (e.g., "ip-dst", "domain").
        :type type_attribute: str
        :param category: The category of the attribute (e.g., "Network activity", "Payload delivery").
        :type category: str, optional
        :param comment: A comment to associate with the attribute.
        :type comment: str, optional
        :param to_ids: If True, the attribute is an indicator that can be used for detection (IDS flag).
                       If False, it's informational. Default is None (MISP's default behavior).
        :type to_ids: bool, optional
        :param distribution: The distribution level of the attribute:
                             0: Your organization only
                             1: This community only
                             2: Connected communities
                             3: All communities
                             4: Sharing group (requires sharing_group_id)
        :type distribution: int, optional
        :param kwargs: Additional keyword arguments to pass for the attribute data
                       (e.g., `object_relation`, `first_seen`, `last_seen`, `sharing_group_id`).
                       Consult PyMISP and MISP API documentation for available fields.
        :return: A dictionary representing the added attribute (the 'Attribute' part of the MISP response)
                 if successful, otherwise None.
        :rtype: dict, optional
        """
        if not isinstance(event_id, (str, int)):
            logger.error("Invalid 'event_id' type for add_attribute. Must be string or integer.")
            return None
        event_id_str = str(event_id) # PyMISP expects string

        if not isinstance(value, str) or not value.strip(): # Value must be a non-empty string
            logger.error("Attribute 'value' must be a non-empty string.")
            return None
        if not isinstance(type_attribute, str): # Type must be a string
            logger.error("Attribute 'type_attribute' must be a string.")
            return None
        self._validate_attribute_type(type_attribute) # Warn if type is unknown

        # Construct the attribute dictionary for PyMISP
        attribute_data = {'value': value, 'type': type_attribute, **kwargs}
        if category: attribute_data['category'] = category
        if comment: attribute_data['comment'] = comment
        if to_ids is not None: attribute_data['to_ids'] = to_ids
        if distribution is not None:
            if isinstance(distribution, int) and 0 <= distribution <= 4: # Standard MISP distribution levels
                attribute_data['distribution'] = distribution
            else:
                logger.warning(f"Invalid distribution value '{distribution}'. Must be an integer between 0 and 4. Distribution parameter will be ignored.")

        # Log a truncated value for potentially long or sensitive attributes
        log_value_display = value[:50] + ('...' if len(value) > 50 else '')
        logger.debug(f"Attempting to add attribute to event {event_id_str}: Type: {type_attribute}, Value: '{log_value_display}', Data: {attribute_data}")
        try:
            # PyMISP's add_attribute expects event_id as string, and attribute data as dict
            response = self.misp.add_attribute(event_id_str, attribute_data)

            # Successful response from PyMISP for add_attribute usually contains an 'Attribute' key
            if response and isinstance(response, dict) and 'Attribute' in response:
                attr_details = response['Attribute']
                logger.info(f"Successfully added attribute ID {attr_details.get('id', 'N/A')} (type: {type_attribute}) to event {event_id_str}.")
                return attr_details # Return the 'Attribute' part of the response
            else:
                # Log error with details from response if available
                error_msg = response.get('errors', response.get('message', 'Unknown error or invalid response')) if isinstance(response, dict) else 'Invalid response format from PyMISP'
                logger.error(f"Failed to add attribute to event {event_id_str}. MISP Response: {error_msg}. Payload sent: {attribute_data}")
                return None
        except MISPAPIError as e: # Errors raised by PyMISP
            logger.error(f"PyMISP API error adding attribute to event {event_id_str}: {e}. Payload: {attribute_data}", exc_info=True)
            return None
        except Exception as e: # Other unexpected errors
            logger.error(f"Unexpected error adding attribute to event {event_id_str}: {e}. Payload: {attribute_data}", exc_info=True)
            return None

    def add_sighting(self, attribute_id: Optional[Union[str, int]] = None, value: Optional[str] = None,
                     source: Optional[str] = None, type_sighting: Optional[str] = '0',
                     **kwargs: Any) -> Optional[Dict[str, Any]]:
        """
        Adds a sighting to an attribute in MISP. Sightings indicate that an attribute
        has been observed (e.g., an IP address seen in logs, a file hash detected).

        You must provide either `attribute_id` (preferred if known) or `value` to identify the attribute.
        If only `value` is provided, MISP will attempt to find a matching attribute to add the sighting to.

        :param attribute_id: The ID of the attribute to add the sighting to.
        :type attribute_id: str or int, optional
        :param value: The value of the attribute to add the sighting to. If `attribute_id` is not
                      provided, MISP will search for an attribute with this value.
        :type value: str, optional
        :param source: The source of the sighting (e.g., "IDS", "Firewall logs", "Analyst observation").
        :type source: str, optional
        :param type_sighting: The type of sighting. MISP uses numeric strings:
                              '0' for True Positive (default), '1' for False Positive.
                              Consult MISP documentation for other possible types.
        :type type_sighting: str, optional
        :param kwargs: Additional keyword arguments to pass to PyMISP's add_sighting method
                       (e.g., `timestamp`, `event_id` if sighting on an attribute within a specific event context).
        :return: A dictionary representing the sighting details as returned by MISP if successful, otherwise None.
                 The structure of this dictionary can vary but often includes 'message' and 'id'.
        :rtype: dict, optional
        """
        if not attribute_id and not value: # Must have one identifier
            logger.error("Either 'attribute_id' or 'value' must be provided for add_sighting.")
            return None

        attr_id_str: Optional[str] = None
        if attribute_id: # Validate and convert attribute_id to string if provided
            if not isinstance(attribute_id, (str, int)):
                logger.error("Invalid 'attribute_id' type. Must be string or integer.")
                return None
            attr_id_str = str(attribute_id)

        if value and not isinstance(value, str): # Value, if provided, must be a string
            logger.error("Invalid 'value' type. Must be a string if provided.")
            return None

        if not (isinstance(type_sighting, str) and type_sighting.isdigit()): # Basic check for sighting type format
             logger.warning(f"Sighting type '{type_sighting}' is not a string digit (e.g., '0', '1'). MISP might reject it if the format is incorrect.")

        logger.debug(f"Attempting to add sighting (type: {type_sighting}, source: {source}) for attribute ID: {attr_id_str} or value: {value}")
        try:
            # PyMISP's add_sighting can take attribute_id, value, or both.
            sighting_response = self.misp.add_sighting(attribute_id=attr_id_str, value=value, source=source, type_sighting=type_sighting, **kwargs)

            # Successful sighting response from PyMISP is typically a dict, often with 'message' and 'id' keys.
            if sighting_response and isinstance(sighting_response, dict):
                msg = sighting_response.get('message', '')
                sighting_id = sighting_response.get('id', 'N/A') # Sighting ID might not always be directly in 'id'

                # Check for common success indicators in the message or presence of an ID.
                # Success messages can vary.
                if 'Sighting added' in msg or 'success' in msg.lower() or (sighting_id != 'N/A' and msg): # Heuristic check
                    logger.info(f"Successfully added sighting. ID: {sighting_id}, Message: '{msg}'")
                    return sighting_response # Return the full response dict from MISP
                # Some PyMISP/MISP versions might just return the sighting object with an ID on success
                elif sighting_id != 'N/A' and not msg: # If ID is there but no specific message
                    logger.info(f"Successfully added sighting. ID: {sighting_id} (No specific message in response)")
                    return sighting_response
                else: # If response doesn't clearly indicate success
                    logger.error(f"Failed to add sighting, MISP response indicates failure or is ambiguous: {sighting_response}")
                    return None
            else: # If response is not a dict or is None/empty
                logger.error(f"Failed to add sighting, unexpected response type or empty response from MISP: {sighting_response}")
                return None
        except MISPAPIError as e: # Errors raised by PyMISP
            logger.error(f"PyMISP API error adding sighting (attr_id: {attr_id_str}, value: {value}): {e}", exc_info=True)
            return None
        except Exception as e: # Other unexpected errors
            logger.error(f"Unexpected error adding sighting (attr_id: {attr_id_str}, value: {value}): {e}", exc_info=True)
            return None

    def download_sample(self, malware_hash: str, event_id: Optional[Union[str, int]] = None) -> Optional[Tuple[str, BytesIO]]:
        """
        Downloads a malware sample from MISP based on its hash (MD5, SHA1, or SHA256).

        WARNING: Downloaded samples can be malicious. Handle with extreme care.
        It is strongly recommended to only download and handle samples in a secure,
        isolated environment designed for malware analysis.

        :param malware_hash: The hash (MD5, SHA1, or SHA256) of the sample to download.
        :type malware_hash: str
        :param event_id: Optional. The ID of the event containing the sample. This can help
                         disambiguate if the hash appears in multiple events, though MISP's
                         sample download by hash is usually direct. If provided, it scopes the search.
        :type event_id: str or int, optional
        :return: A tuple containing (filename: str, file_data: io.BytesIO) if successful.
                 The `file_data` is an in-memory binary stream of the sample.
                 Returns (None, None) if the sample is not found or an error occurs.
        :rtype: tuple (str, io.BytesIO), optional
        """
        if not malware_hash or not isinstance(malware_hash, str): # Hash must be a non-empty string
            logger.error("Invalid or empty 'malware_hash' provided. Must be a non-empty string.")
            return None, None # Explicitly return tuple for type consistency

        event_id_str: Optional[str] = None # Ensure event_id is string for PyMISP if provided
        if event_id:
            if not isinstance(event_id, (str, int)):
                logger.error("Invalid 'event_id' type for download_sample. Must be string or integer if provided.")
                return None, None
            event_id_str = str(event_id)

        logger.warning(f"Attempting to download sample with hash: {malware_hash} (Event: {event_id_str}). HANDLE WITH EXTREME CARE.")
        try:
            # PyMISP's download_samples returns a list of tuples: (filename, malware_binary_io_BytesIO)
            # We expect one sample if hash is specific, or the first one if multiple match.
            # `searchall=malware_hash` is used to find the sample by its hash value across events (if event_id is not specified).
            download_results = self.misp.download_samples(searchall=malware_hash, event_id=event_id_str)

            if download_results and isinstance(download_results, list) and len(download_results) > 0:
                # Assuming the first result is the desired one if multiple are returned for a hash.
                filename, file_object_bytesio = download_results[0]

                # Validate the structure of the returned tuple
                if isinstance(filename, str) and isinstance(file_object_bytesio, BytesIO):
                    file_size = file_object_bytesio.getbuffer().nbytes if hasattr(file_object_bytesio, 'getbuffer') else -1
                    logger.info(f"Successfully downloaded sample: '{filename}' (Size: {file_size} bytes)")
                    return filename, file_object_bytesio
                else:
                    logger.error(f"Downloaded sample result for hash {malware_hash} has an unexpected item format: Filename type '{type(filename)}', Object type '{type(file_object_bytesio)}'")
                    return None, None # Explicitly return tuple
            else: # No results found or empty list returned
                logger.warning(f"Sample with hash '{malware_hash}' (Event: {event_id_str}) not found or download failed. MISP Result: {download_results}")
                return None, None # Explicitly return tuple
        except MISPAPIError as e: # Errors raised by PyMISP
            logger.error(f"PyMISP API error downloading sample with hash '{malware_hash}': {e}", exc_info=True)
            return None, None
        except Exception as e: # Other unexpected errors
            logger.error(f"Unexpected error downloading sample with hash '{malware_hash}': {e}", exc_info=True)
            return None, None

# __main__ block for testing purposes
if __name__ == '__main__':
    # Setup basic logging for testing if no handlers are configured by an importing application.
    # This allows the script to show log output when run directly.
    if not logging.getLogger(__name__).hasHandlers(): # Check if handlers are already configured
        logging.basicConfig(
            level=os.getenv("MISP_CLIENT_LOG_LEVEL", "INFO").upper(),  # Default to INFO, configurable via env var
            format='%(asctime)s - %(name)s - %(levelname)s - %(module)s.%(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        # For more detailed PyMISP debug logs during testing (can be very verbose):
        # logging.getLogger('pymisp').setLevel(logging.DEBUG)
        # logging.getLogger('requests').setLevel(logging.DEBUG) # For underlying requests library

    logger.info("Attempting to initialize MISP Client for testing...")

    # Fetch configuration from environment variables for testing
    misp_url_env = os.getenv("MISP_URL")
    misp_key_env = os.getenv("MISP_API_KEY")
    # Optional: proxy configuration for testing network paths
    misp_proxy_env = os.getenv("PYMISP_DEBUG_PROXIES")
    test_proxies_dict = {'http': misp_proxy_env, 'https': misp_proxy_env} if misp_proxy_env else None


    if not misp_url_env or not misp_key_env:
        logger.critical("CRITICAL: MISP_URL and MISP_API_KEY environment variables must be set for testing this script.")
        logger.info("Example: export MISP_URL=\"https://your-misp-instance.com\"") # Corrected example URL
        logger.info("Example: export MISP_API_KEY=\"your-api-key\"")
        logger.info("Optional for testing: export PYMISP_DEBUG_PROXIES=\"http://your_proxy_url:port\"")
        logger.info("Optional for testing: export MISP_CLIENT_LOG_LEVEL=\"DEBUG\" for more detailed logs.")
    else:
        try:
            # Initialize client (can pass url/key/proxies directly here to override env vars if needed for specific tests)
            client = MISPClient(misp_url=misp_url_env, misp_api_key=misp_key_env, proxies=test_proxies_dict)
            logger.info("MISP Client initialized successfully for __main__ tests.")

            # --- Test get_event ---
            logger.info("\n--- Testing get_event ---")
            # Use environment variables for test parameters to avoid hardcoding sensitive or instance-specific IDs
            test_event_id_exists = os.getenv("MISP_TEST_EXISTING_EVENT_ID", "1") # Default to '1' if not set
            event = client.get_event(test_event_id_exists)
            if event:
                logger.info(f"Get Event (Exists Test) ID '{test_event_id_exists}': Found - Info: {event.get('info', 'N/A')[:60]}...")
            else:
                logger.warning(f"Get Event (Exists Test) ID '{test_event_id_exists}': Not Found or Error. (Ensure MISP_TEST_EXISTING_EVENT_ID is set to a valid event ID in your MISP instance).")

            test_event_id_nonexistent = os.getenv("MISP_TEST_NONEXISTENT_EVENT_ID", "999999999") # A very unlikely event ID
            event_nonexistent = client.get_event(test_event_id_nonexistent)
            if not event_nonexistent:
                logger.info(f"Get Event (Non-existent Test) ID '{test_event_id_nonexistent}': Correctly Not Found or Error.")
            else:
                logger.error(f"Get Event (Non-existent Test) ID '{test_event_id_nonexistent}': Unexpectedly Found - Info: {event_nonexistent.get('info')}")

            # --- Test search_events ---
            logger.info("\n--- Testing search_events (by attribute type) ---")
            search_attr_type = os.getenv("MISP_TEST_SEARCH_ATTR_TYPE", "ip-src") # Default search type
            events_by_attr = client.search_events(controller='attributes', type_attribute=search_attr_type, limit=2, published=1) # Search for published events
            if events_by_attr:
                logger.info(f"Search Events (type '{search_attr_type}', published): Found {len(events_by_attr)} events.")
            else:
                logger.info(f"Search Events (type '{search_attr_type}', published): No events found. (Consider adding data or changing MISP_TEST_SEARCH_ATTR_TYPE).")

            logger.info("\n--- Testing search_events (by tag) ---")
            search_tag = os.getenv("MISP_TEST_SEARCH_TAG", "tlp:green") # Common TLP tag
            events_by_tag = client.search_events(controller='events', tags=[search_tag], limit=1, published=1) # Search for published events
            if events_by_tag:
                logger.info(f"Search Events (tag '{search_tag}', published): Found {len(events_by_tag)} events.")
            else:
                logger.info(f"Search Events (tag '{search_tag}', published): No events found (Ensure MISP_TEST_SEARCH_TAG is a tag present in your published MISP events).")

            # --- Test add_attribute (requires a valid event_id with write access) ---
            # This test modifies data, so it's often commented out or run against a test MISP instance.
            event_to_add_to = os.getenv("MISP_TEST_ADD_ATTR_EVENT_ID")
            if event_to_add_to:
                logger.info(f"\n--- Testing add_attribute (to event ID: {event_to_add_to}) ---")
                # First, verify the event exists to avoid errors if the ID is wrong
                if client.get_event(event_to_add_to):
                    unique_test_value = f"test-client-domain-{os.urandom(4).hex()}.com" # Generate a unique value for testing
                    added_attr_details = client.add_attribute(
                        event_id=event_to_add_to,
                        value=unique_test_value,
                        type_attribute="domain",
                        category="Network activity",
                        comment="Automated misp_client.py test attribute",
                        to_ids=False, # Typically False for domains unless it's a known C2
                        distribution=0  # Distribution 0 = Your organization only
                    )
                    if added_attr_details:
                        logger.info(f"Add Attribute: Success - ID {added_attr_details.get('id')} (value: '{unique_test_value}') added to event {event_to_add_to}")

                        # --- Test add_sighting (using the newly added attribute's ID) ---
                        # This also modifies data.
                        logger.info("\n--- Testing add_sighting ---")
                        attr_id_for_sighting = added_attr_details.get('id')
                        if attr_id_for_sighting:
                            sighting_details = client.add_sighting(attribute_id=attr_id_for_sighting, source="Automated misp_client.py Test Sighting")
                            if sighting_details:
                                logger.info(f"Add Sighting: Success - Response: {sighting_details.get('message', sighting_details.get('id', 'OK'))}")
                            else:
                                logger.error(f"Add Sighting: Failed for attribute ID {attr_id_for_sighting}.")
                        else:
                            logger.error("Add Sighting: Skipped - could not retrieve ID from the attribute added in the previous step.")
                    else:
                        logger.error(f"Add Attribute: Failed for event {event_to_add_to} with value '{unique_test_value}'. Check permissions and event status.")
                else:
                    logger.warning(f"Skipping Add Attribute/Sighting tests: Event {event_to_add_to} (from MISP_TEST_ADD_ATTR_EVENT_ID) not found or not accessible.")
            else: # If MISP_TEST_ADD_ATTR_EVENT_ID is not set
                logger.info("\nSkipping Add Attribute/Sighting tests: MISP_TEST_ADD_ATTR_EVENT_ID environment variable not set.")

            # --- Test download_sample (use a known HASH if available and if you are in a safe environment) ---
            # This test involves downloading potentially malicious files. EXTREME CAUTION ADVISED.
            known_sample_hash_for_download = os.getenv("MISP_TEST_DOWNLOAD_HASH")
            if known_sample_hash_for_download:
                logger.info("\n--- Testing download_sample ---")
                logger.warning(f"Attempting to download sample with hash: {known_sample_hash_for_download}. ENSURE THIS IS A SAFE OPERATION IN YOUR ENVIRONMENT.")
                filename, sample_data_stream = client.download_sample(known_sample_hash_for_download)
                if filename and sample_data_stream:
                    logger.info(f"Download Sample: Success - Filename: '{filename}', Size: {sample_data_stream.getbuffer().nbytes} bytes. (Sample data is in memory, NOT saved to disk by this test script)")
                    # To save (example, use with caution):
                    # with open(f"downloaded_{filename}", "wb") as f:
                    #     f.write(sample_data_stream.getvalue())
                else:
                    logger.warning(f"Download Sample: Failed or sample not found for hash '{known_sample_hash_for_download}'.")
            else: # If MISP_TEST_DOWNLOAD_HASH is not set
                logger.info("\nSkipping Download Sample test: MISP_TEST_DOWNLOAD_HASH environment variable not set.")

            logger.info("\n--- All configured __main__ tests completed ---")

        except ValueError as ve: # From our own validation in __init__ or methods
            logger.critical(f"Critical Configuration or Value Error during testing: {ve}", exc_info=True)
        except MISPError as me: # Base class for MISP related errors from PyMISP
            logger.critical(f"MISP Client Critical Error during testing: {me}", exc_info=True)
        except ConnectionError as ce: # From our __init__ for unexpected connection issues
            logger.critical(f"MISP Client Connection Error during testing: {ce}", exc_info=True)
        except Exception as e: # Catch-all for any other unexpected errors during the test run
            logger.critical(f"An unexpected critical error occurred during __main__ testing: {e}", exc_info=True)
