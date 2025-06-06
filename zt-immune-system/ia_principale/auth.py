# zt-immune-system/ia_principale/auth.py
"""
Handles JWT-based authentication for the IA Principale module, particularly for WebSockets.

This module provides functions to:
- Create JWT access tokens with configurable expiry and custom claims.
- Verify JWT access tokens, checking for signature, expiry, and other standard claims.
- A FastAPI dependency (`get_current_user_ws`) to authenticate WebSocket connections
  using a token passed as a query parameter. This dependency ensures that
  WebSocket connections are only established for authenticated users.

Configuration for JWT (secret key, algorithm, token expiry) is primarily sourced
from environment variables, with fallback defaults suitable for development environments.
It's crucial to set strong, unique secrets for production deployments.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import WebSocket, status
from fastapi.exceptions import WebSocketException
from jose import JWTError, jwt # Using python-jose for JWT handling

# Configure logger for this module
logger = logging.getLogger(__name__)
# Ensure basicConfig is called only if no handlers are configured for the root logger
# or this specific logger. This helps prevent overriding Uvicorn's logging if it's already set up.
if not logging.getLogger().hasHandlers() and not logger.hasHandlers():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
    )

# --- JWT Configuration ---
# IMPORTANT: SECRET_KEY should be kept secret and managed securely, ideally via environment variables.
# For production, use a strong, randomly generated key.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-default-super-secret-key-for-dev") # TODO: Change this default for any real deployment
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256") # Standard and secure algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30")) # Default to 30 minutes

if SECRET_KEY == "your-default-super-secret-key-for-dev":
    logger.warning(
        "Security Risk: Using default JWT SECRET_KEY. "
        "This is highly insecure and MUST be changed for any production or sensitive environment. "
        "Set the JWT_SECRET_KEY environment variable to a strong, unique secret."
    )

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a new JWT access token with specified data and expiry.

    Args:
        data: Dictionary containing the data to include in the token's payload (claims).
              A 'sub' (subject) claim will be automatically added from `data['user_id']`
              if 'sub' is not already present in `data`.
        expires_delta: Optional timedelta to specify the token's lifespan. If None,
                       uses `ACCESS_TOKEN_EXPIRE_MINUTES` from the module configuration.

    Returns:
        The encoded JWT string.

    Raises:
        Exception: Propagates any exceptions that occur during JWT encoding after logging.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,  # Expiration time
        "iat": now,     # Issued at time
        "nbf": now      # Not before time (token is valid from this point)
    })

    # Ensure 'sub' (subject) claim, commonly used for user identifier
    if "sub" not in to_encode and "user_id" in to_encode:
        to_encode["sub"] = str(to_encode["user_id"])
    elif "sub" not in to_encode:
        # It's good practice for tokens to have a subject.
        logger.warning("Creating JWT without a 'sub' claim or 'user_id' in data. This might affect user identification in consuming services.")

    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.debug(f"Created access token for subject: {to_encode.get('sub', 'N/A')}, expiring at {expire.isoformat()}")
        return encoded_jwt
    except Exception as e:
        logger.exception("Critical error occurred during JWT encoding process.") # Log with stack trace
        raise # Re-raise the original exception to signal failure to the caller

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies the integrity, signature, and validity (e.g., expiry) of a JWT token.

    Args:
        token: The JWT string to verify.

    Returns:
        The decoded token payload (claims dictionary) if the token is valid in all aspects.
        Returns None if verification fails for any reason (e.g., expired, invalid signature,
        malformed token, or other JWT errors).
    """
    if not token: # Handle empty or None token string explicitly
        logger.debug("Token verification attempted with an empty or None token string.")
        return None
    try:
        # jwt.decode handles signature, expiry, and basic structure validation.
        # It also checks 'nbf' if present.
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM] # Specify a list of allowed algorithms
            # Options for audience ('aud') or issuer ('iss') can be added here if used:
            # options={"verify_aud": True, "verify_iss": True},
            # audience="my_api_audience",
            # issuer="my_auth_server_identifier"
        )
        logger.debug(f"Token successfully decoded and verified for subject: {payload.get('sub', 'N/A')}")
        return payload
    except jwt.ExpiredSignatureError:
        # Logged specifically as it's a common case.
        logger.warning(f"Token verification failed: Expired signature. Token snippet: {token[:30]}...")
        return None
    except jwt.JWTClaimsError as e:
        # Handles errors in standard claims if they are invalid format or fail checks (e.g. nbf, exp, iat).
        logger.warning(f"Token verification failed: Invalid claims. Error: {e}. Token snippet: {token[:30]}...")
        return None
    except JWTError as e:
        # Catches other JWT-related errors (e.g., invalid signature, malformed token, wrong algorithm if not in list).
        logger.warning(f"Token verification failed: Invalid token ({type(e).__name__}). Error: {e}. Token snippet: {token[:30]}...")
        return None
    except Exception as e:
        # Catch any other unexpected errors during decoding, potentially due to malformed token structure
        # not caught by JWTError, or other system issues.
        logger.exception(f"Unexpected error during token verification. Token snippet: {token[:30]}... Error: {e}")
        return None


async def get_current_user_ws(websocket: WebSocket) -> Dict[str, Any]:
    """
    FastAPI dependency to authenticate WebSocket connections using a JWT from query parameters.

    This function attempts to extract a JWT from the 'token' query parameter of the
    WebSocket connection URL. It then verifies the token's validity using `verify_token`.
    If authentication is successful, it returns the token's payload, typically containing
    user identification and other claims. If authentication fails for any reason
    (e.g., token missing, invalid, expired, or missing essential claims like 'sub'),
    it closes the WebSocket connection with an appropriate error code and message,
    and then raises a `WebSocketException` to terminate the connection attempt.

    Args:
        websocket: The `fastapi.WebSocket` instance representing the client connection.

    Returns:
        A dictionary containing the decoded JWT payload (claims) if authentication is successful.

    Raises:
        WebSocketException: If authentication fails, signaling FastAPI to close the connection.
    """
    token = websocket.query_params.get("token")

    if not token:
        logger.warning(f"WebSocket connection attempt from {websocket.client} without 'token' query parameter.")
        # Send close frame before raising to ensure client gets a reason.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing authentication token in query parameters.")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Missing authentication token in query parameters."
        )

    payload = verify_token(token)
    if payload is None:
        # verify_token logs the specific reason for failure (e.g., expired, invalid signature).
        logger.warning(f"WebSocket connection authentication failed for client {websocket.client} due to invalid/expired token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid, expired, or malformed token.")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Invalid, expired, or malformed token."
        )

    # Ensure 'sub' (subject) claim, typically user identifier, is present in the payload.
    user_id = payload.get("sub")
    if not user_id:
        logger.error(
            f"WebSocket connection from {websocket.client}: "
            "Authenticated token is valid but missing the 'sub' (subject) claim, "
            "which is required for user identification."
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token missing required user identification ('sub' claim).")
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Token missing required user identification ('sub' claim)."
        )

    logger.info(f"WebSocket authentication successful for user '{user_id}' (sub claim) from client {websocket.client}.")
    # The returned payload can be used by the WebSocket endpoint if it includes `user: Dict = Depends(get_current_user_ws)`.
    return payload


# Example usage (for testing this module directly if run as a script)
if __name__ == "__main__":
    # Ensure logging is configured for standalone testing output
    if not logging.getLogger().hasHandlers(): # Check root logger
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    logger.info("Auth module direct execution for testing token creation/verification.")

    # Test token creation
    user_data_valid = {"user_id": "testuser123", "username": "testuser", "roles": ["user"], "custom_data": "example_value"}
    logger.info(f"Creating token for data: {user_data_valid}")
    test_token_valid = create_access_token(user_data_valid)
    logger.info(f"Generated valid test token: {test_token_valid}")

    # Test token verification (valid token)
    logger.info("\n--- Verifying the generated valid token ---")
    payload_valid = verify_token(test_token_valid)
    if payload_valid:
        logger.info(f"Token verified successfully. Payload: {payload_valid}")
        assert payload_valid["sub"] == "testuser123", "Subject claim mismatch"
        assert payload_valid["custom_data"] == "example_value", "Custom claim mismatch"
    else:
        logger.error("Valid token verification FAILED.")

    # Test with an explicitly malformed token
    logger.info("\n--- Verifying a malformed token ---")
    malformed_token = "this.is.not.a.valid.jwt.token"
    payload_malformed = verify_token(malformed_token)
    if payload_malformed:
        logger.error(f"Malformed token somehow verified. Payload: {payload_malformed}") # Should not happen
    else:
        logger.info("Malformed token verification failed as expected.")

    # Test with an expired token
    logger.info("\n--- Verifying an expired token (token created to be already expired) ---")
    user_data_expired = {"user_id": "expired_user", "username": "expired_test"}
    # Create a token that expired 5 minutes ago
    expired_token = create_access_token(user_data_expired, expires_delta=timedelta(minutes=-5))
    logger.info(f"Generated an expired test token: {expired_token}")
    payload_expired = verify_token(expired_token)
    if payload_expired:
        logger.error(f"Expired token somehow verified. Payload: {payload_expired}") # Should not happen
    else:
        logger.info("Expired token verification failed as expected.")

    # Test token with a different secret key (simulating tampering)
    logger.info("\n--- Verifying a token signed with a different secret key ---")
    user_data_tampered = {"user_id": "tampered_user", "username": "tampered_test"}
    another_secret = "another-completely-different-secret-key-!@#$%^"
    # Ensure the test secret is different from the one verify_token will use (SECRET_KEY from env or default)
    if another_secret == SECRET_KEY:
        logger.warning("Skipping wrong secret test as test secret is same as module SECRET_KEY. Adjust test for meaningful results.")
    else:
        now_ts = datetime.now(timezone.utc)
        tampered_claims = {
            **user_data_tampered,
            "sub": "tampered_user", # Ensure sub claim
            "exp": now_ts + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat": now_ts,
            "nbf": now_ts
        }
        token_wrong_secret = jwt.encode(tampered_claims, another_secret, algorithm=ALGORITHM)
        logger.info(f"Generated token with wrong secret: {token_wrong_secret}")
        payload_wrong_secret = verify_token(token_wrong_secret)
        if payload_wrong_secret:
            logger.error(f"Token with wrong secret somehow verified. Payload: {payload_wrong_secret}")
        else:
            logger.info("Token signed with wrong secret failed verification as expected.")

    logger.info("\nTo test get_current_user_ws fully, integrate with a running FastAPI app and a WebSocket client.")
    logger.info("Auth module direct execution tests finished.")
