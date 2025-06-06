import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

# Adjust imports based on your project structure
from zt_immune_system.ia_principale.auth import (
    create_access_token,
    verify_token,
    SECRET_KEY,       # Assuming this is the key used by verify_token
    ALGORITHM,        # Assuming this is the algorithm used by verify_token
    TEST_SECRET_KEY,  # This should be the one from conftest for creating test tokens
    TEST_ALGORITHM    # This should be the one from conftest
)
# Or, if conftest already patches os.environ and auth.py re-reads it:
# from zt_immune_system.ia_principale.auth import create_access_token, verify_token, SECRET_KEY, ALGORITHM
# And rely on conftest's os.environ patching to make SECRET_KEY == TEST_SECRET_KEY

# It's safer if create_access_token used by tests explicitly uses the test key/algo,
# or if verify_token can be parameterized with the key/algo for testing.
# For this example, we'll assume conftest.py sets os.environ["JWT_SECRET_KEY"] = TEST_SECRET_KEY
# and auth.py's SECRET_KEY picks that up when auth.py is imported/used.

# Use the test key and algorithm defined in conftest.py for creating tokens for tests
# This ensures consistency if the main SECRET_KEY in auth.py is different or loaded dynamically.
# If auth.py defines SECRET_KEY at module level from os.environ, conftest should set that env var.
# The create_access_token in auth.py will then use it.

def test_create_and_verify_valid_token():
    """Test creating a token and then verifying it successfully."""
    user_data = {"sub": "testuser@example.com", "user_id": "user123", "custom_claim": "custom_value"}

    # Assuming create_access_token uses the SECRET_KEY and ALGORITHM from auth.py,
    # and these are effectively the TEST_SECRET_KEY and TEST_ALGORITHM due to conftest.py's setup.
    token = create_access_token(data=user_data.copy())
    assert token is not None

    # Verify the token using the application's verify_token function
    payload = verify_token(token)
    assert payload is not None
    assert payload["sub"] == user_data["sub"]
    assert payload["user_id"] == user_data["user_id"]
    assert payload["custom_claim"] == user_data["custom_claim"]
    assert "exp" in payload
    assert "iat" in payload

def test_verify_expired_token(test_auth_config):
    """Test that an expired token fails verification."""
    # Create a token that is already expired
    expired_user_data = {"sub": "expired@example.com", "user_id": "expired_user"}
    # Use the actual create_access_token from auth.py, ensuring it uses the test key for this test scenario
    # This relies on auth.SECRET_KEY being TEST_SECRET_KEY for the test session
    expired_token = create_access_token(data=expired_user_data, expires_delta=timedelta(minutes=-5))

    payload = verify_token(expired_token)
    assert payload is None, "Expired token should not validate"

def test_verify_token_invalid_signature(test_auth_config):
    """Test that a token with an invalid signature fails verification."""
    user_data = {"sub": "testuser@example.com", "user_id": "user123"}
    # Create a token with the correct test secret key
    token = create_access_token(data=user_data.copy())

    # Attempt to verify with a different secret key (simulating tampering or misconfiguration)
    # This requires verify_token to use the application's actual SECRET_KEY.
    # We need to ensure that the SECRET_KEY used by verify_token is different from
    # a hypothetical "wrong_secret_key" for this test to be meaningful.

    # If verify_token internally uses the global SECRET_KEY from auth.py,
    # we can't directly pass a different key to verify_token for this specific test call.
    # Instead, we can create a token with a *different* key and try to verify it.

    wrong_secret = "this-is-a-wrong-secret-key-for-sure"
    # Ensure this wrong_secret is different from the one verify_token will use (TEST_SECRET_KEY)
    assert wrong_secret != TEST_SECRET_KEY

    tampered_token = jwt.encode(
        claims=user_data,
        key=wrong_secret, # Signed with a different key
        algorithm=TEST_ALGORITHM
    )

    payload = verify_token(tampered_token)
    assert payload is None, "Token with invalid signature should not validate"

def test_verify_token_malformed():
    """Test that a malformed token string fails verification."""
    malformed_token = "this.is.not.a.valid.jwt.token"
    payload = verify_token(malformed_token)
    assert payload is None, "Malformed token should not validate"

    empty_token = ""
    payload_empty = verify_token(empty_token)
    assert payload_empty is None, "Empty token string should not validate"

    none_token = None
    # verify_token expects a string, so passing None might raise TypeError before JWTError
    # Depending on how strictly we want to test verify_token's input handling:
    with pytest.raises(Exception): # Catches TypeError or any other error if None is not handled before decode
         verify_token(none_token)
    # Or, if None should gracefully return None from verify_token:
    # assert verify_token(None) is None


def test_verify_token_different_algorithm(test_auth_config):
    """Test token signed with a different algorithm if the server expects only one."""
    user_data = {"sub": "algo_test@example.com", "user_id": "algo_user"}

    # Current ALGORITHM used by create_access_token (from auth.py, hopefully TEST_ALGORITHM)
    # Let's try to encode with HS512 if current is HS256, or vice-versa.
    different_algo = "HS512" if TEST_ALGORITHM == "HS256" else "HS256"

    # Create token with a different algorithm
    # Note: python-jose's jwt.encode uses the specified algorithm.
    # verify_token in auth.py decodes with algorithms=[ALGORITHM] (singular).
    # If ALGORITHM in auth.py is 'HS256', a token signed with 'HS512' should fail.

    token_alt_algo = jwt.encode(
        claims={**user_data, "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
        key=TEST_SECRET_KEY, # Use the correct test key
        algorithm=different_algo
    )

    payload = verify_token(token_alt_algo)
    assert payload is None, f"Token signed with {different_algo} should not validate if server expects {ALGORITHM}"


# Placeholder for testing get_current_user_ws
# This would typically require mocking FastAPI's WebSocket and its query_params,
# or performing an integration test with TestClient.
def test_get_current_user_ws_conceptual():
    """Conceptual outline for testing get_current_user_ws."""
    # 1. Mock WebSocket object
    # class MockWebSocket:
    #     def __init__(self, token=None, client_host="testclient", client_port=12345):
    #         self.query_params = {"token": token} if token else {}
    #         self.client = (client_host, client_port)
    #     async def close(self, code, reason): pass # Mock close

    # 2. Test with valid token:
    #    - Create a valid token.
    #    - mock_ws = MockWebSocket(token=valid_token)
    #    - user = await get_current_user_ws(mock_ws)
    #    - Assert user is not None and contains expected payload.

    # 3. Test with missing token:
    #    - mock_ws = MockWebSocket(token=None)
    #    - with pytest.raises(WebSocketException): await get_current_user_ws(mock_ws)

    # 4. Test with invalid/expired token:
    #    - Create an invalid/expired token.
    #    - mock_ws = MockWebSocket(token=invalid_token)
    #    - with pytest.raises(WebSocketException): await get_current_user_ws(mock_ws)
    pass

# Note: The actual SECRET_KEY and ALGORITHM used by create_access_token and verify_token
# in the auth.py module are critical. If they are module-level constants,
# the conftest.py setup that patches os.environ must ensure these are correctly
# influenced BEFORE auth.py is imported by any test module.
# A common robust solution is to have settings/config be injectable or part of an app context.
# The current tests assume that TEST_SECRET_KEY and TEST_ALGORITHM from conftest.py
# are effectively what's being used by the auth functions during testing.
