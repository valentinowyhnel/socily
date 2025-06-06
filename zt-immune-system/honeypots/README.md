# ZT Immune System - Honeypots Module

## Overview

This directory contains a collection of diverse honeypots, containerized using Docker and orchestrated with Docker Compose. The primary goal is to provide a modular and extensible setup for deploying various types of honeypots to capture and analyze different attack vectors.

The setup is designed to be easily deployable and manageable, leveraging Docker for isolation and Docker Compose for service definition and orchestration.

## Prerequisites

Before you begin, ensure you have the following installed:
-   **Docker:** [Installation Guide](https://docs.docker.com/engine/install/)
-   **Docker Compose:** [Installation Guide](https://docs.docker.com/compose/install/)

## Included Honeypots

This setup currently includes the following honeypots, each in its own subdirectory:

-   **Cowrie (`./cowrie`)**:
    -   A medium to high interaction SSH and Telnet honeypot designed to log brute force attacks and shell interaction performed by the attacker.
    -   Homepage: [Cowrie GitHub](https://github.com/cowrie/cowrie)
-   **mhnet (`./mhnet`)**:
    -   A placeholder for a custom honeypot or a sensor for the Modern Honey Network (MHN).
    -   The `mhnet_setup.sh` script is intended to be customized by the user to deploy their desired honeypot service.
-   **T-Pot (`./tpot`)**:
    -   Provides a basic environment to run T-Pot components. T-Pot itself is a multi-honeypot platform.
    -   This is a placeholder and requires significant user configuration within `tpot/start.sh` and `tpot/config.yaml` to deploy a functional T-Pot instance or selected components.
    -   Homepage: [T-Pot GitHub](https://github.com/telekom-security/tpotce)

## Directory Structure

```
zt-immune-system/
├── honeypots/
│   ├── docker-compose.yml  # Main Docker Compose file for orchestrating honeypots
│   ├── cowrie/             # Cowrie honeypot specific files (Dockerfile, config, etc.)
│   │   ├── Dockerfile
│   │   ├── cowrie.cfg      # Default Cowrie configuration (built into image)
│   │   └── start_cowrie.sh # Script to start Cowrie
│   ├── mhnet/              # Placeholder for custom/MHN honeypot
│   │   ├── Dockerfile
│   │   └── mhnet_setup.sh  # User-defined setup and execution script
│   ├── tpot/               # Placeholder for T-Pot components
│   │   ├── Dockerfile
│   │   ├── config.yaml     # Placeholder T-Pot configuration
│   │   └── start.sh        # Placeholder T-Pot startup script
│   └── README.md           # This file
└── infrastructure/
    └── docker/
        ├── seccomp_profile.json # Default seccomp profile for containers
        ├── apparmor_profile.conf # Example AppArmor profile
        └── selinux_policy.te    # Example SELinux policy type enforcement file
```

-   **`docker-compose.yml`**: Defines the services, networks, and volumes for the honeypot deployment.
-   **`cowrie/`**: Contains the Dockerfile, default `cowrie.cfg`, and startup script for the Cowrie honeypot.
-   **`mhnet/`**: Contains a generic Dockerfile and `mhnet_setup.sh` which must be populated by the user to deploy a specific honeypot.
-   **`tpot/`**: Contains a generic Dockerfile, a placeholder `config.yaml`, and `start.sh` for users to integrate T-Pot or its components.

## Getting Started

1.  **Build the Docker images:**
    Open a terminal in the `zt-immune-system/honeypots/` directory and run:
    ```bash
    docker-compose build
    ```

2.  **Start the honeypot services:**
    To start the services in detached mode:
    ```bash
    docker-compose up -d
    ```

3.  **Check the status of running services:**
    ```bash
    docker-compose ps
    ```

4.  **View logs for a specific service:**
    For example, to view Cowrie logs:
    ```bash
    docker-compose logs cowrie
    docker-compose logs -f cowrie # To follow logs
    ```

5.  **Stop and remove the services:**
    ```bash
    docker-compose down
    ```
    To remove volumes as well (deletes persisted data):
    ```bash
    docker-compose down -v
    ```

## Configuration & Customization

### General

-   **Environment Variables**: Common service configurations (like hostnames or service identifiers) can be set via environment variables in the `docker-compose.yml` file for each service.

### Cowrie (`./cowrie`)

-   **Configuration File**: The primary configuration for Cowrie is `cowrie/cowrie.cfg`. A default version is built into the Docker image at `/home/cowrie/cowrie/etc/cowrie.cfg.dist`.
-   **Overriding Configuration**: To customize the Cowrie configuration, you can:
    1.  Modify `cowrie/cowrie.cfg` **before building the image**.
    2.  Or, for runtime changes without rebuilding, uncomment the volume mount in `docker-compose.yml` to map your local `cowrie/cowrie.cfg` to `/home/cowrie/cowrie/etc/cowrie.cfg.dist` (or `/home/cowrie/cowrie/cowrie.cfg` depending on how Cowrie loads it, typically it's `.dist` then copied).
        ```yaml
        # In docker-compose.yml services.cowrie.volumes:
        # - ./cowrie/cowrie.cfg:/home/cowrie/cowrie/etc/cowrie.cfg.dist:ro
        ```
-   **Hostname**: The `COWRIE_HOSTNAME` environment variable in `docker-compose.yml` can be used by Cowrie if its configuration is set up to read it (the provided `cowrie.cfg` sets a static hostname).

### mhnet (`./mhnet`)

-   **Setup Script**: The core logic for this honeypot resides in `mhnet/mhnet_setup.sh`. You need to populate this script with commands to install dependencies, configure, and run your chosen honeypot service.
-   **Environment Variable**: `MHNET_SERVICE_NAME` in `docker-compose.yml` is an example of how you might pass configuration to your setup script.

### T-Pot (`./tpot`)

-   **Startup Script & Config**: Customization happens in `tpot/start.sh` and `tpot/config.yaml`. These are placeholders and require user implementation to deploy T-Pot components.
-   **Complexity**: A full T-Pot deployment is complex and may require:
    -   Additional Docker capabilities (e.g., `cap_add: [NET_ADMIN, NET_RAW]`).
    -   Specific network configurations (host mode, many port mappings).
    -   Potentially Docker-in-Docker (mounting `/var/run/docker.sock`), which has significant security implications.
    -   Adjustments to `sysctls`.
    The current Dockerfile and service definition are minimal and provide a basic environment.
-   **Environment Variable**: `TPOT_FLAVOR` in `docker-compose.yml` is an example for use in `start.sh`.

## Logging

-   **Cowrie**: Configured to output JSON logs to `stdout` by default (see `cowrie/cowrie.cfg`). These can be accessed via `docker-compose logs cowrie`.
-   **mhnet / T-Pot**: Logging behavior is dependent on the user's implementation within the respective `mhnet_setup.sh` and `tpot/start.sh` scripts. It's recommended to configure these services to log to `stdout`/`stderr` for easy collection with `docker-compose logs`.

## Security Considerations

Security is paramount when deploying honeypots, as they are intentionally exposed to attract malicious activity.

-   **Container Security**:
    -   `no-new-privileges:true`: Prevents containers from gaining new privileges.
    -   `seccomp` profile: A default seccomp profile (`../infrastructure/docker/seccomp_profile.json`) is applied to restrict allowed syscalls, reducing the kernel attack surface.
-   **Further Enhancements (System-Level)**:
    -   **AppArmor**: Consider applying AppArmor profiles (example: `../infrastructure/docker/apparmor_profile.conf`) for mandatory access control.
    -   **SELinux**: If your host uses SELinux, custom SELinux policies (example: `../infrastructure/docker/selinux_policy.te`) can provide more granular control.
-   **Network Isolation**:
    -   It is crucial to isolate the honeypot network from your production networks. The `honeynet` Docker bridge network provides basic isolation at the Docker level.
    -   Ensure your host firewall rules are configured to only expose intended honeypot ports to the desired zones (e.g., internet-facing, internal segments).
    -   **Never expose management interfaces of Docker or the host system to untrusted networks.**
-   **Resource Limits**: Configure resource limits (CPU, memory) in `docker-compose.yml` for each service to prevent a compromised honeypot from consuming excessive host resources.

## Data Persistence

-   **Cowrie**: Persists data (like downloaded malware, TTY logs if not to stdout) to the `cowrie_data` Docker volume, mounted at `/home/cowrie/cowrie/var/lib/cowrie`.
-   **mhnet**: A `mhnet_data` volume is defined and can be used by the custom script in `mhnet_setup.sh` by mounting it to an appropriate path (e.g., `/opt/mhnet/data`).
-   **T-Pot**: Data persistence for T-Pot is complex and depends on the deployed components. The `tpot_data` volume is commented out in `docker-compose.yml` and should be specifically configured by the user as needed.

## Flexibility and Extensibility

-   **`mhnet` as a Template**: The `mhnet` service is a flexible template. You can adapt `mhnet/Dockerfile` and `mhnet/mhnet_setup.sh` to run virtually any honeypot that can be containerized.
-   **`tpot` as an Environment**: The `tpot` service provides a starting point for integrating components of the T-Pot framework or other complex honeypot distributions.
-   **Adding New Honeypots**: To add a new honeypot:
    1.  Create a new subdirectory (e.g., `./myhoneypot/`).
    2.  Add a `Dockerfile` and any necessary configuration/startup scripts within it.
    3.  Define a new service in `docker-compose.yml` similar to the existing ones.

---

Remember to regularly update the base images and honeypot software to patch vulnerabilities and get the latest features.
Happy honeypotting!
