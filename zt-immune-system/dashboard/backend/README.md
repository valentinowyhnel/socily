# ZT Immune System - Dashboard Backend

## Overview

This FastAPI application serves as the backend for the ZT Immune System Dashboard. Its primary responsibilities include:
- Providing RESTful APIs for the frontend dashboard to fetch data and interact with the system.
- Handling user authentication and authorization using JWT.
- Serving as a WebSocket endpoint for real-time communication with the frontend (e.g., for alerts or agent status updates).
- Potentially acting as a gateway or proxy to other backend components or Kafka topics in some scenarios, though direct Kafka interaction is minimal in the current design (primarily handled by `ia_principale`).

## Technologies Used

- **Python 3.9+**: The core programming language.
- **FastAPI**: A modern, fast (high-performance) web framework for building APIs with Python.
- **Uvicorn**: An ASGI server used to run the FastAPI application.
- **`python-jose[cryptography]`**: For encoding, decoding, and verifying JWTs (JSON Web Tokens) for authentication.
- **`passlib[bcrypt]`**: For securely hashing and verifying user passwords.
- **`kafka-python`**: (Currently listed in the main project `requirements.txt`). While direct Kafka operations by this specific backend module are limited, the overall system relies on Kafka, and this dependency might be used if direct interaction becomes necessary.

**Note on Dependencies**: A dedicated `requirements.txt` for this backend module (`zt-immune-system/dashboard/backend/requirements.txt`) should be created. Currently, dependencies like `fastapi`, `uvicorn`, `python-jose[cryptography]`, and `passlib[bcrypt]` are assumed to be installed in the environment or would need to be added to a relevant `requirements.txt` file (either project-level or module-level).

## Prerequisites

- **Python**: Version 3.9 or newer is recommended.
- **`pip`**: The Python package installer (usually comes with Python).
- **Virtual Environment (Recommended)**: To manage project dependencies in isolation.
- **Access to a Kafka Broker**: While this backend doesn't heavily interact with Kafka directly, the overall ZT Immune System does. The frontend dashboard may display data that originates from or is passed through Kafka via other components.

## Project Setup and Installation

1.  **Navigate to the backend directory**:
    ```bash
    cd zt-immune-system/dashboard/backend
    ```

2.  **Create and activate a Python virtual environment**:
    ```bash
    python -m venv venv
    ```
    Activate the environment:
    -   Linux/macOS: `source venv/bin/activate`
    -   Windows: `venv\Scripts\activate`

3.  **Install dependencies**:
    *Ideally, there would be a `zt-immune-system/dashboard/backend/requirements.txt` file.*
    If not, you'll need to install the necessary packages manually or from the main project's `requirements.txt` (if it's updated to include FastAPI and related dependencies):
    ```bash
    # Example if a specific requirements.txt existed here:
    # pip install -r requirements.txt

    # Manual installation of core dependencies (if no backend-specific requirements.txt):
    pip install fastapi uvicorn[standard] python-jose[cryptography] passlib[bcrypt]
    # Add kafka-python if direct interaction is planned for this module.
    ```

## Configuration

Key configuration aspects, primarily managed within the Python files or via environment variables:

-   **`SECRET_KEY`**:
    -   Defined in: `auth.py`
    -   Purpose: Used for signing and verifying JWTs.
    -   **Security Note**: The placeholder value **MUST** be changed to a strong, unique secret key for any production or security-sensitive environment.
-   **`ACCESS_TOKEN_EXPIRE_MINUTES`**:
    -   Defined in: `auth.py`
    -   Purpose: Sets the expiration time for JWT access tokens (default is 30 minutes).
-   **`API_PORT`**:
    -   The port for the Uvicorn server is typically passed as a command-line argument when running Uvicorn (e.g., `--port 8001`).
    -   The `if __name__ == "__main__":` block in `app.py` uses port `8001` by default if run as `python app.py`.
-   **`KAFKA_BROKER_ADDRESS`**:
    -   While not heavily used by this specific backend module currently, if direct Kafka interaction were added (e.g., for publishing specific dashboard-related events), this environment variable would be the standard way to configure the Kafka broker address (defaulting to `localhost:9092`).

## Running the Application

To run the backend server for development:

1.  Ensure your virtual environment is activated.
2.  Navigate to the `zt-immune-system/dashboard/backend/` directory.
3.  Run Uvicorn:
    ```bash
    uvicorn app:app --reload --host 0.0.0.0 --port 8001
    ```
    -   `app:app`: Tells Uvicorn to find the FastAPI instance named `app` in the file `app.py`.
    -   `--reload`: Enables auto-reloading when code changes are detected (useful for development).
    -   `--host 0.0.0.0`: Makes the server accessible from other machines on the network (not just `localhost`).
    -   `--port 8001`: Specifies the port to run on.

Alternatively, if the `if __name__ == "__main__":` block in `app.py` is configured to run Uvicorn (as it is in this project):
```bash
python app.py
```
This will typically start the server on `0.0.0.0:8001` with settings defined within `app.py`.

## API Endpoints & Documentation

The backend exposes several API endpoints:

-   **`/token`**: (POST)
    -   Handles user authentication. Expects form data with `username` and `password`.
    -   Returns a JWT access token upon successful authentication.
-   **`/api/...`**: (Various methods: GET, POST)
    -   These routes are defined in `api_routes.py` and are prefixed with `/api`.
    -   They handle interactions related to the ZT Immune System's core functionalities, such as:
        -   Fetching system status (`/api/status`)
        -   Managing alerts (`/api/alerts`, `/api/alerts/{alert_id}`)
        -   Listing agents (`/api/agents`) and their logs (`/api/agents/{agent_id}/logs`)
        -   Retrieving AI decisions and IOCs.
        -   Executing commands (`/api/commands`).
        -   Ingesting threat intelligence feeds (`/api/intel/misp_feed`).
    -   These endpoints are secured using JWT authentication and role-based access control defined in `auth.py`.
-   **`/api/agents/status`**: (WebSocket)
    -   Defined in `app.py`.
    -   A WebSocket endpoint for streaming real-time updates (e.g., new alerts, agent status changes) to connected frontend clients.

FastAPI automatically generates interactive API documentation, which is extremely useful for development and testing:

-   **Swagger UI**: Accessible at `/docs` (e.g., `http://localhost:8001/docs`).
-   **ReDoc**: Accessible at `/redoc` (e.g., `http://localhost:8001/redoc`).

## Directory Structure

Key files in the `zt-immune-system/dashboard/backend/` directory:

-   **`app.py`**:
    -   The main FastAPI application instance is created and configured here.
    -   Includes middleware (e.g., CORS).
    -   Defines the `/token` authentication endpoint.
    -   Defines the WebSocket endpoint (`/api/agents/status`).
    -   Includes the router from `api_routes.py`.
    -   Contains the Uvicorn startup logic for direct execution (`if __name__ == "__main__":`).
-   **`api_routes.py`**:
    -   Defines the primary set of RESTful API routes prefixed with `/api`.
    -   Contains Pydantic models for request/response data structures for these routes.
    -   Implements placeholder logic for interacting with AI components (to be replaced with actual business logic).
    -   Endpoints are secured using dependencies from `auth.py`.
-   **`auth.py`**:
    -   Handles all authentication and authorization logic.
    -   Includes JWT creation and verification.
    -   Manages password hashing and user lookup (currently using a placeholder user database).
    -   Defines Pydantic models for users and tokens.
    -   Provides dependency functions for FastAPI to protect routes and implement role-based access control (RBAC).
-   **`requirements.txt` (Recommended)**:
    -   A file that *should* exist to list all Python dependencies for this specific backend module (e.g., `fastapi`, `uvicorn`, `python-jose[cryptography]`, `passlib[bcrypt]`).

---
*This README provides an overview specific to the dashboard backend. For information about the entire ZT Immune System project, refer to the main README.md in the project root.*
