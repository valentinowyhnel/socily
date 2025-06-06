import pytest
import os
from datetime import timedelta

from fastapi.testclient import TestClient

# Adjust imports based on your actual project structure
# It's assumed that your project root is added to PYTHONPATH when running pytest
# or that you are running pytest from the project root.
try:
    from zt_immune_system.ia_principale.main import app
    from zt_immune_system.ia_principale.auth import create_access_token, SECRET_KEY, ALGORITHM
except ImportError:
    # This is a fallback if the tests are run in a way that system path isn't correctly configured.
    # For robust CI/CD, ensure PYTHONPATH is set up correctly.
    import sys
    # Assuming the script is run from the project root or 'zt-immune-system' is in the path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from zt_immune_system.ia_principale.main import app
    from zt_immune_system.ia_principale.auth import create_access_token, SECRET_KEY, ALGORITHM

# Ensure consistent JWT settings for testing
# These should match what your application expects or what you set for testing.
# If your auth.py loads from os.environ, you might set them here before auth module is loaded,
# or ensure your test environment has them set.
TEST_SECRET_KEY = "test_jwt_secret_key_for_conftest" # Use a dedicated test secret
TEST_ALGORITHM = "HS256"

# Override auth module's constants if they are defined at module level and not loaded dynamically
# This is a bit hacky. A better way is to use dependency injection for settings in your app.
# For now, if auth.py defines SECRET_KEY and ALGORITHM as global constants,
# test tokens created here must use the same values as the auth.py module expects.
# If auth.py loads them from os.environ, then setting os.environ here before import might work,
# or rely on the test environment setup.

# Monkeypatch os.environ for the auth module if it reads SECRET_KEY and ALGORITHM from there at import time.
# This needs to be done BEFORE the auth module is imported by any test or fixture.
# However, since `create_access_token` is imported above, this might be too late if auth.py
# already read the original os.environ.
# A common pattern is to have settings injectable into your auth functions or classes.

# For simplicity in this example, we assume create_access_token can be called with test values,
# or that the auth module will pick up these env vars if pytest is configured to set them.
os.environ["JWT_SECRET_KEY"] = TEST_SECRET_KEY
os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = "15" # Shorter expiry for tests

# Re-import auth if it needs to pick up the new env vars (if it loads them at import time)
# This is generally not a good practice; dependency injection for settings is preferred.
# import importlib
# from zt_immune_system.ia_principale import auth
# importlib.reload(auth)
# create_access_token = auth.create_access_token


@pytest.fixture(scope="module")
def test_client_instance():
    """
    Provides a FastAPI TestClient instance for the entire test module.
    Ensures that lifespan events (startup/shutdown) are run for the module.
    """
    # Ensure environment variables are set before TestClient instantiates the app,
    # if your app's config depends on them at import time or startup.
    # os.environ["KAFKA_BROKER_ADDRESS"] = "mock_kafka:9092" # Example for Kafka

    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="session") # Changed to session for potentially wider re-use
def test_auth_config():
    return {"secret_key": TEST_SECRET_KEY, "algorithm": TEST_ALGORITHM}

@pytest.fixture(scope="module")
def valid_jwt_token_for_test_user(test_auth_config):
    """
    Generates a valid JWT for a test user.
    """
    # Use the overridden SECRET_KEY and ALGORITHM for creating test tokens
    # This ensures consistency if auth.py's global constants were not successfully patched.
    # For this to work reliably, create_access_token should ideally accept key/algo as params,
    # or auth.py should use a settings object that can be replaced during tests.

    # Assuming create_access_token uses the globally defined SECRET_KEY from auth.py,
    # ensure that SECRET_KEY in auth.py is effectively TEST_SECRET_KEY for tests.
    # This conftest tries to achieve this by setting os.environ, assuming auth.py
    # re-evaluates os.environ["JWT_SECRET_KEY"] when create_access_token is called,
    # or that it was imported after os.environ was set.

    # A more robust way:
    # from zt_immune_system.ia_principale.auth import _create_access_token_for_test
    # return _create_access_token_for_test(data={"sub": "testuser@example.com", "user_id": "testuser123"},
    #                                      secret_key=TEST_SECRET_KEY,
    #                                      algorithm=TEST_ALGORITHM)
    # This would require a helper in auth.py or making create_access_token more flexible.

    # For now, we rely on the global auth.SECRET_KEY being effectively the TEST_SECRET_KEY
    # due to the os.environ patching at the start of this conftest.py.
    # Note: This is a common point of failure in testing setups if not handled carefully.
    return create_access_token(data={"sub": "testuser@example.com", "user_id": "testuser123", "roles": ["test_role"]})

@pytest.fixture(scope="module")
def expired_jwt_token_for_test_user(test_auth_config):
    """
    Generates an expired JWT for a test user.
    """
    return create_access_token(
        data={"sub": "expireduser@example.com", "user_id": "expireduser123"},
        expires_delta=timedelta(minutes=-30) # Token expired 30 minutes ago
    )

# If you need to mock specific dependencies globally for tests, you can do it here.
# For example, mocking KafkaProducer:
# @pytest.fixture(autouse=True, scope="module")
# def mock_kafka_producer(module_mocker):
#     if "KAFKA_BROKER_ADDRESS" not in os.environ: # Ensure it's set for test environment
#         os.environ["KAFKA_BROKER_ADDRESS"] = "mock://kafka_test:9092"
#     mock = module_mocker.patch("zt_immune_system.ia_principale.communication.kafka_client.KafkaProducerWrapper")
#     mock.return_value.send_message.return_value = True # Mock successful send
#     mock.return_value.producer = True # Simulate producer is initialized
#     return mock

# Note on imports: Adjust the import paths like `zt_immune_system.ia_principale.main`
# according to how pytest discovers your modules. If `zt-immune-system` is the root
# of your project and pytest runs from there, these paths should work if `zt-immune-system`
# itself is not a package but a directory in PYTHONPATH.
# If `zt_immune_system` is a package, then `from zt_immune_system.ia_principale...` is correct.
# If your project root is `ia_principale`'s parent, then it might be `from ia_principale.main import app`.
# The current structure assumes `zt-immune-system` is the top-level directory in PYTHONPATH.
