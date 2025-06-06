import os
import unittest
from unittest.mock import patch, MagicMock, mock_open, call # Added call
import warnings
import logging
from io import BytesIO # Added BytesIO

# Ensure the client can be imported.
from zt_immune_system.threat_intel.misp_client import MISPClient, MISPError, MISPAPIError, VALID_MISP_ATTRIBUTE_TYPES

# Suppress warnings during tests for cleaner output, specifically the UserWarning for non-HTTPS URLs.
# warnings.simplefilter("ignore", UserWarning) # Keep this commented unless specifically debugging warnings

# Disable logging for most tests unless specifically testing logging output
# Critical logs will still show up if not handled by the client, which is good.
logging.disable(logging.CRITICAL)


class TestMISPClientInit(unittest.TestCase):
    """Tests for MISPClient initialization and connection setup."""

    @patch.dict(os.environ, {"MISP_URL": "https://fake-misp.com", "MISP_API_KEY": "fake_key"})
    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def test_init_success_env_vars(self, mock_pymisp_constructor):
        """Test successful initialization using environment variables."""
        mock_misp_instance = MagicMock()
        mock_misp_instance.get_server_settings.return_value = {'server': {'version': '2.4.170'}}
        mock_pymisp_constructor.return_value = mock_misp_instance

        client = MISPClient()
        self.assertEqual(client.misp_url, "https://fake-misp.com")
        self.assertEqual(client.misp_api_key, "fake_key")
        mock_pymisp_constructor.assert_called_once_with(
            "https://fake-misp.com", "fake_key", ssl=True, proxies=None, debug=False
        )
        mock_misp_instance.get_server_settings.assert_called_once()

    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def test_init_success_constructor_args(self, mock_pymisp_constructor):
        """Test successful initialization using constructor arguments."""
        mock_misp_instance = MagicMock()
        mock_misp_instance.get_server_settings.return_value = {'server': {'version': '2.4.170'}}
        mock_pymisp_constructor.return_value = mock_misp_instance

        client = MISPClient(misp_url="https://another-misp.com", misp_api_key="another_key", proxies={"https": "proxy.com"})
        self.assertEqual(client.misp_url, "https://another-misp.com")
        self.assertEqual(client.misp_api_key, "another_key")
        mock_pymisp_constructor.assert_called_once_with(
            "https://another-misp.com", "another_key", ssl=True, proxies={"https": "proxy.com"}, debug=False
        )
        mock_misp_instance.get_server_settings.assert_called_once()

    @patch.dict(os.environ, {}, clear=True) # Ensure no env vars are present
    def test_init_missing_url_key_raises_value_error(self):
        """Test ValueError is raised if URL or key is missing."""
        with self.assertRaisesRegex(ValueError, "MISP_URL and MISP_API_KEY must be provided"):
            MISPClient()
        with self.assertRaisesRegex(ValueError, "MISP_URL and MISP_API_KEY must be provided"):
            MISPClient(misp_url="https://url.com") # Key missing
        with self.assertRaisesRegex(ValueError, "MISP_URL and MISP_API_KEY must be provided"):
            MISPClient(misp_api_key="key") # URL missing

    @patch.dict(os.environ, {"MISP_URL": "http://insecure-misp.com", "MISP_API_KEY": "fake_key"})
    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def test_init_non_https_url_warns_and_sets_ssl_false(self, mock_pymisp_constructor):
        """Test non-HTTPS URL issues a warning and attempts connection with ssl=False."""
        mock_misp_instance = MagicMock()
        mock_misp_instance.get_server_settings.return_value = {'server': {'version': '2.4.170'}}
        mock_pymisp_constructor.return_value = mock_misp_instance

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always", UserWarning) # Capture UserWarnings
            client = MISPClient() # noqa: F841
            self.assertTrue(len(w) >= 1, "Warning not issued for non-HTTPS URL")
            self.assertTrue(any(issubclass(warn.category, UserWarning) and "should use HTTPS" in str(warn.message) for warn in w))

        mock_pymisp_constructor.assert_called_with(
            "http://insecure-misp.com", "fake_key", ssl=False, proxies=None, debug=False
        )

    @patch.dict(os.environ, {"MISP_URL": "https://fake-misp.com", "MISP_API_KEY": "fake_key"})
    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def test_init_pymisp_api_error(self, mock_pymisp_constructor):
        """Test MISPAPIError during PyMISP instantiation is re-raised."""
        mock_pymisp_constructor.side_effect = MISPAPIError("API Auth Failed")
        with self.assertRaisesRegex(MISPAPIError, "API Auth Failed"):
            MISPClient()

    @patch.dict(os.environ, {"MISP_URL": "https://fake-misp.com", "MISP_API_KEY": "fake_key"})
    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def test_init_pymisp_generic_error(self, mock_pymisp_constructor):
        """Test generic MISPError during PyMISP instantiation is re-raised."""
        mock_pymisp_constructor.side_effect = MISPError("Generic MISP connection issue")
        with self.assertRaisesRegex(MISPError, "Generic MISP connection issue"):
            MISPClient()

    @patch.dict(os.environ, {"MISP_URL": "https://fake-misp.com", "MISP_API_KEY": "fake_key"})
    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def test_init_connection_check_fails(self, mock_pymisp_constructor):
        """Test connection failure if get_server_settings fails."""
        mock_misp_instance = MagicMock()
        mock_misp_instance.get_server_settings.side_effect = MISPError("Cannot get server settings")
        mock_pymisp_constructor.return_value = mock_misp_instance

        with self.assertRaisesRegex(MISPError, "Cannot get server settings"):
            MISPClient()


class BaseMISPClientTestCase(unittest.TestCase):
    """Base class for tests that need a MISPClient instance with mocked PyMISP."""
    @patch.dict(os.environ, {"MISP_URL": "https://fake-misp.com", "MISP_API_KEY": "fake_key"})
    @patch('zt_immune_system.threat_intel.misp_client.PyMISP')
    def setUp(self, mock_pymisp_constructor):
        # Create a mock for the PyMISP instance, using spec for attribute checking if desired
        self.mock_misp_internal_instance = MagicMock(spec=PyMISP) # spec=PyMISP can help catch typos if methods change
        self.mock_misp_internal_instance.get_server_settings.return_value = {'server': {'version': '2.4.170'}}

        # Configure the constructor mock to return our instance mock
        mock_pymisp_constructor.return_value = self.mock_misp_internal_instance

        # Store the constructor mock itself if we need to assert calls to PyMISP()
        self.mock_pymisp_constructor = mock_pymisp_constructor

        self.client = MISPClient() # This will call PyMISP() which returns our mock_misp_internal_instance

        # Reset call counts for the internal mock's methods before each test method
        self.mock_misp_internal_instance.reset_mock()
        # We need to re-mock get_server_settings because reset_mock clears side_effect/return_value,
        # and __init__ might be called again implicitly or explicitly in some complex test setups.
        # For simple cases, this might not be strictly necessary if client is only init'd once in setUp.
        self.mock_misp_internal_instance.get_server_settings.return_value = {'server': {'version': '2.4.170'}}


class TestMISPClientGetEvent(BaseMISPClientTestCase):
    """Tests for the MISPClient get_event method."""

    def test_get_event_success(self):
        mock_event_data = {"Event": {"id": "123", "info": "Test Event"}}
        self.mock_misp_internal_instance.get_event.return_value = mock_event_data

        event = self.client.get_event("123")
        self.assertEqual(event, mock_event_data["Event"])
        self.mock_misp_internal_instance.get_event.assert_called_once_with("123")

    def test_get_event_not_found_404_error(self):
        self.mock_misp_internal_instance.get_event.return_value = {'errors': [404, {"message": "Not Found"}]}
        event = self.client.get_event("unknown_id")
        self.assertIsNone(event)

    def test_get_event_not_found_empty_dict(self):
        self.mock_misp_internal_instance.get_event.return_value = {}
        event = self.client.get_event("unknown_id_2")
        self.assertIsNone(event)

    def test_get_event_api_error(self):
        self.mock_misp_internal_instance.get_event.side_effect = MISPAPIError("API access denied")
        event = self.client.get_event("123")
        self.assertIsNone(event)

    def test_get_event_unexpected_error(self):
        self.mock_misp_internal_instance.get_event.side_effect = Exception("Something broke")
        event = self.client.get_event("123")
        self.assertIsNone(event)

    def test_get_event_invalid_id_type(self):
        event = self.client.get_event([123]) # type: ignore
        self.assertIsNone(event)
        self.mock_misp_internal_instance.get_event.assert_not_called()


class TestMISPClientSearchEvents(BaseMISPClientTestCase):
    """Tests for the MISPClient search_events method."""

    def test_search_events_success_controller_events(self):
        mock_response = [{"Event": {"id": "1", "info": "Event 1"}}, {"Event": {"id": "2", "info": "Event 2"}}]
        self.mock_misp_internal_instance.search.return_value = mock_response

        events = self.client.search_events(controller='events', tags=["Test"])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['info'], "Event 1")
        self.mock_misp_internal_instance.search.assert_called_once_with(controller='events', tags=["Test"])

    def test_search_events_success_controller_attributes_fetches_events(self):
        mock_attributes_response = [
            {'Attribute': {"event_id": "10", "value": "1.2.3.4"}}, # PyMISP often nests under 'Attribute'
            {'Attribute': {"event_id": "11", "value": "evil.com"}}
        ]
        # If search returns direct attribute dicts (less common for pymisp.search but good to cover)
        # mock_attributes_response_direct = [
        #     {"event_id": "10", "value": "1.2.3.4"},
        #     {"event_id": "11", "value": "evil.com"}
        # ]

        mock_event10_data = {"Event": {"id": "10", "info": "Event for 1.2.3.4"}}
        mock_event11_data = {"Event": {"id": "11", "info": "Event for evil.com"}}

        self.mock_misp_internal_instance.search.return_value = mock_attributes_response
        # Mock subsequent get_event calls made by search_events for controller='attributes'
        self.mock_misp_internal_instance.get_event.side_effect = [mock_event10_data, mock_event11_data]

        events = self.client.search_events(controller='attributes', value="1.2.3.4")
        self.assertEqual(len(events), 2)
        self.assertTrue(any(e['id'] == "10" for e in events))
        self.assertTrue(any(e['id'] == "11" for e in events))
        self.mock_misp_internal_instance.search.assert_called_once_with(controller='attributes', value="1.2.3.4")
        self.mock_misp_internal_instance.get_event.assert_has_calls([call("10"), call("11")], any_order=True)

    def test_search_events_no_results(self):
        self.mock_misp_internal_instance.search.return_value = []
        events = self.client.search_events(controller='events', value="nonexistentValue")
        self.assertEqual(len(events), 0)

    def test_search_events_api_error(self):
        self.mock_misp_internal_instance.search.side_effect = MISPAPIError("Search operation failed")
        events = self.client.search_events(value="any_value")
        self.assertEqual(len(events), 0) # Expect empty list on error

    def test_search_events_invalid_input_types(self):
        # Test various invalid input types that should be caught by client-side validation
        self.assertEqual(self.client.search_events(value=12345), [])
        self.assertEqual(self.client.search_events(type_attribute=987), [])
        self.assertEqual(self.client.search_events(tags="this-is-not-a-list"), [])
        self.assertEqual(self.client.search_events(tags=[1,2,3]), [])
        # Ensure PyMISP's search method was not called for these invalid inputs
        self.mock_misp_internal_instance.search.assert_not_called()


class TestMISPClientAddAttribute(BaseMISPClientTestCase):
    """Tests for the MISPClient add_attribute method."""

    def test_add_attribute_success(self):
        mock_response = {"Attribute": {"id": "attr_new_1", "value": "evil-test.com", "type": "domain"}}
        self.mock_misp_internal_instance.add_attribute.return_value = mock_response

        attribute_params = {"value": "evil-test.com", "type": "domain", "category": "Network activity"}
        added_attr = self.client.add_attribute("event_id_123", **attribute_params)

        self.assertEqual(added_attr, mock_response["Attribute"])
        self.mock_misp_internal_instance.add_attribute.assert_called_once_with("event_id_123", attribute_params)

    def test_add_attribute_failure_api_error(self):
        self.mock_misp_internal_instance.add_attribute.side_effect = MISPAPIError("Failed to add attribute due to API restriction")
        added_attr = self.client.add_attribute("event_id_456", "bad-value.com", "domain")
        self.assertIsNone(added_attr)

    def test_add_attribute_failure_bad_response_structure(self):
        # Simulate a response from MISP that doesn't contain the 'Attribute' key
        self.mock_misp_internal_instance.add_attribute.return_value = {"errors": "Some MISP error occurred"}
        added_attr = self.client.add_attribute("event_id_789", "another-value.com", "domain")
        self.assertIsNone(added_attr)

    def test_add_attribute_invalid_input_values(self):
        self.assertIsNone(self.client.add_attribute("event1", "", "domain")) # Empty value string
        self.assertIsNone(self.client.add_attribute("event1", "   ", "domain")) # Whitespace only value string
        self.assertIsNone(self.client.add_attribute("event1", "valid_val", type_attribute=12345)) # Invalid type_attribute type
        # Ensure PyMISP's add_attribute was not called for these invalid inputs
        self.mock_misp_internal_instance.add_attribute.assert_not_called()

    @patch('zt_immune_system.threat_intel.misp_client.logger') # Patch logger to check for warnings
    def test_add_attribute_with_unknown_type_logs_warning(self, mock_logger_instance):
        # This test checks if the _validate_attribute_type (which logs a warning) is triggered.
        # It doesn't prevent the call to misp.add_attribute.
        self.mock_misp_internal_instance.add_attribute.return_value = {"Attribute": {"id":"temp"}} # Ensure it doesn't fail on this
        self.client.add_attribute("event_id_abc", "some_custom_value", "highly-custom-attribute-type")
        mock_logger_instance.warning.assert_called() # Check if logger.warning was called
        self.assertIn("highly-custom-attribute-type", mock_logger_instance.warning.call_args[0][0])


class TestMISPClientAddSighting(BaseMISPClientTestCase):
    """Tests for the MISPClient add_sighting method."""

    def test_add_sighting_success_by_attribute_id(self):
        mock_sighting_response = {"message": "Sighting successfully added.", "id": "sighting_id_1"}
        self.mock_misp_internal_instance.add_sighting.return_value = mock_sighting_response

        sighting_result = self.client.add_sighting(attribute_id="attr_id_xyz", source="TestSourceSystem")

        self.assertEqual(sighting_result, mock_sighting_response)
        self.mock_misp_internal_instance.add_sighting.assert_called_once_with(
            attribute_id="attr_id_xyz", value=None, source="TestSourceSystem", type_sighting='0'
        )

    def test_add_sighting_success_by_value(self):
        mock_sighting_response = {"message": "Sighting added for value.", "id": "sighting_id_2"}
        self.mock_misp_internal_instance.add_sighting.return_value = mock_sighting_response

        sighting_result = self.client.add_sighting(value="10.20.30.40", type_sighting='1', source="AnotherSource")

        self.assertEqual(sighting_result, mock_sighting_response)
        self.mock_misp_internal_instance.add_sighting.assert_called_once_with(
            attribute_id=None, value="10.20.30.40", source="AnotherSource", type_sighting='1'
        )

    def test_add_sighting_failure_api_error(self):
        self.mock_misp_internal_instance.add_sighting.side_effect = MISPAPIError("MISP API denied sighting addition")
        sighting_result = self.client.add_sighting(attribute_id="attr_id_789")
        self.assertIsNone(sighting_result)

    def test_add_sighting_failure_bad_response_structure(self):
        # Simulate a MISP response that doesn't indicate success clearly
        self.mock_misp_internal_instance.add_sighting.return_value = {"errors": "Error during sighting creation"}
        sighting_result = self.client.add_sighting(attribute_id="attr_id_abc")
        self.assertIsNone(sighting_result)

    def test_add_sighting_invalid_input_parameters(self):
        self.assertIsNone(self.client.add_sighting()) # Both attribute_id and value are missing
        self.assertIsNone(self.client.add_sighting(attribute_id=["invalid_type"])) # attribute_id is not str/int
        self.assertIsNone(self.client.add_sighting(value=12345)) # value is not str
        # Ensure PyMISP's add_sighting was not called for these invalid inputs
        self.mock_misp_internal_instance.add_sighting.assert_not_called()


class TestMISPClientDownloadSample(BaseMISPClientTestCase):
    """Tests for the MISPClient download_sample method."""

    def test_download_sample_success(self):
        mock_sample_content = b"This is a test sample content."
        # PyMISP's download_samples returns a list of tuples
        mock_pymisp_response = [("sample_file.exe", BytesIO(mock_sample_content))]
        self.mock_misp_internal_instance.download_samples.return_value = mock_pymisp_response

        filename, file_data_obj = self.client.download_sample("test_sample_hash")

        self.assertEqual(filename, "sample_file.exe")
        self.assertIsInstance(file_data_obj, BytesIO)
        self.assertEqual(file_data_obj.read(), mock_sample_content)
        self.mock_misp_internal_instance.download_samples.assert_called_once_with(
            searchall="test_sample_hash", event_id=None
        )

    def test_download_sample_not_found_empty_list(self):
        self.mock_misp_internal_instance.download_samples.return_value = [] # Empty list indicates not found
        filename, file_data_obj = self.client.download_sample("non_existent_hash")
        self.assertIsNone(filename)
        self.assertIsNone(file_data_obj)

    def test_download_sample_api_error(self):
        self.mock_misp_internal_instance.download_samples.side_effect = MISPAPIError("Sample download forbidden by API")
        filename, file_data_obj = self.client.download_sample("any_hash")
        self.assertIsNone(filename)
        self.assertIsNone(file_data_obj)

    def test_download_sample_bad_response_item_format(self):
        # Simulate PyMISP returning a list with an incorrectly formatted tuple
        self.mock_misp_internal_instance.download_samples.return_value = [("filename_only_no_bytesio_object")]
        filename, file_data_obj = self.client.download_sample("another_hash")
        self.assertIsNone(filename)
        self.assertIsNone(file_data_obj)

    def test_download_sample_invalid_input_hash(self):
        self.assertTupleEqual(self.client.download_sample(malware_hash=None), (None, None))
        self.assertTupleEqual(self.client.download_sample(malware_hash=""), (None, None)) # Empty hash string
        self.assertTupleEqual(self.client.download_sample(malware_hash=12345), (None, None)) # Hash is not a string
        # Ensure PyMISP's download_samples was not called for these invalid inputs
        self.mock_misp_internal_instance.download_samples.assert_not_called()


class TestMISPClientHelpers(BaseMISPClientTestCase): # Inherits setUp with client
    """Tests for helper methods like _validate_attribute_type."""

    def test_validate_attribute_type_known_type(self):
        # This method currently logs a warning for unknown types but always returns True.
        # So, for a known type, it should return True and ideally not log.
        # We can't easily assert "not logged" without more complex logger mocking for specific levels.
        # However, we primarily care that it doesn't prevent valid operations.
        self.assertTrue(self.client._validate_attribute_type("ip-dst"))
        # To be more thorough, one might check that logger.warning was NOT called here.

    @patch('zt_immune_system.threat_intel.misp_client.logger') # Patch the logger used in misp_client.py
    def test_validate_attribute_type_unknown_type_logs_warning(self, mock_client_logger):
        # Test that an unknown attribute type logs a warning.
        unknown_type = "this-is-a-super-custom-unknown-type"
        self.assertTrue(self.client._validate_attribute_type(unknown_type)) # Method should still return True

        # Assert that logger.warning was called
        mock_client_logger.warning.assert_called_once()
        # Assert that the warning message contains the unknown type string
        self.assertIn(unknown_type, mock_client_logger.warning.call_args[0][0])


if __name__ == '__main__':
    # To run tests with more verbose logging output from the client itself (for debugging):
    # logging.disable(logging.NOTSET) # This would re-enable all logging
    # logging.getLogger('zt_immune_system.threat_intel.misp_client').setLevel(logging.DEBUG)
    unittest.main()
