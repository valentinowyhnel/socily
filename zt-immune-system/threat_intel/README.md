# Threat Intel Module

This module is responsible for interacting with threat intelligence platforms and fetching/processing threat data.

## MISP Client (`misp_client.py`)

### Configuration

The MISP client requires the following environment variables to be set:

- `MISP_URL`: The URL of your MISP instance (e.g., https://misp.example.com)
- `MISP_API_KEY`: Your MISP API automation key.

Make sure these are set in the environment where the client will run.
