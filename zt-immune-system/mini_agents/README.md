# ZT Immune System - Mini Agents

## Overview

Mini Agents are specialized, often autonomous or semi-autonomous, components of the ZT Immune System. They are responsible for performing specific cybersecurity tasks at various points within the monitored environment. These tasks can range from detection of suspicious activities and in-depth analysis of potential threats, to executing response actions and facilitating continuous learning for the AI models.

All Mini Agents are designed to communicate with the **IA Principale (Main AI)** primarily via an **Apache Kafka** message bus, receiving tasks and sending back results or alerts.

## General Configuration

Most, if not all, Mini Agents will require the following general configuration:

-   **Kafka Broker Address**: The `KAFKA_BROKER_ADDRESS` environment variable must be set to the address(es) of your Kafka broker(s) to enable communication with the IA Principale and other components.
    -   Example: `export KAFKA_BROKER_ADDRESS="localhost:9092"`
-   **Python Environment**: Each agent is typically a separate Python application.
    -   It is highly recommended to manage dependencies using Python virtual environments. You can create a dedicated virtual environment for each agent or use a shared virtual environment if dependencies are largely common and compatible.
    -   Ensure the `kafka-python` library is installed in the environment used to run the agent. Other dependencies will be specific to each agent's functionality.
    -   **Note on Dependencies**: Ideally, each agent directory (e.g., `agent_detection/`, `agent_analysis/`) should contain its own `requirements.txt` file listing its specific Python dependencies. If not, these dependencies must be manually installed or included in a shared `requirements.txt` file used by the chosen virtual environment. The main project `requirements.txt` currently only lists `kafka-python`.

## Implemented Agents

Below is a list of currently implemented or planned Mini Agents:

### Detection Agent (`agent_detection/`)

-   **Purpose**: This agent is responsible for monitoring systems, network traffic, or log sources for suspicious activities, known malware patterns (e.g., using YARA rules - conceptual), or violations of security rules (e.g., Sigma rules - conceptual).
-   **Communication**:
    -   Publishes alerts and detected events to the `alerts_raw` Kafka topic, which are then consumed by the IA Principale.
    -   (Future) May subscribe to a tasking topic like `agent_tasks_detection` for dynamic configuration updates or specific on-demand scan requests from the IA Principale.
-   **Running**:
    1.  Ensure `KAFKA_BROKER_ADDRESS` is set.
    2.  Navigate to the agent's directory: `cd zt-immune-system/mini_agents/agent_detection`
    3.  Activate the appropriate Python virtual environment.
    4.  Run the agent: `python detector.py`

### Analysis Agent (`agent_analysis/`)

-   **Purpose**: This agent performs in-depth analysis on specific Indicators of Compromise (IOCs), files, or other event data when tasked by the IA Principale. This might involve sandboxing, static/dynamic malware analysis, or querying external threat intelligence sources.
-   **Communication**:
    -   Subscribes to tasks on the `agent_tasks_analysis` Kafka topic, which are dispatched by the IA Principale's Orchestrator.
    -   (Placeholder for results) Analysis results would typically be published back to the IA Principale via a dedicated Kafka topic (e.g., `analysis_results`) or potentially an API endpoint on the Main AI.
-   **Running**:
    1.  Ensure `KAFKA_BROKER_ADDRESS` is set.
    2.  Navigate to the agent's directory: `cd zt-immune-system/mini_agents/agent_analysis`
    3.  Activate the appropriate Python virtual environment.
    4.  Run the agent: `python analyzer.py`

### Response Agent (`agent_response/responder.py`)

-   **Purpose (Conceptual)**: Executes automated or semi-automated response actions based on decisions from the IA Principale (e.g., blocking an IP address via firewall integration, isolating a compromised host, disabling a user account).
-   **Communication (Conceptual)**: Would subscribe to tasks on `agent_tasks_response` and report action status.

### Learning Agent (`agent_learning/learner.py`)

-   **Purpose (Conceptual)**: Facilitates distributed machine learning tasks, such as local model training, data pre-processing for central AI learning, or federated learning contributions.
-   **Communication (Conceptual)**: Would subscribe to tasks on `agent_tasks_learning` and publish model updates or learning data.

### Deployment Agent (`agent_deployment/deployer.py`)

-   **Purpose (Conceptual)**: Manages the deployment, update, and lifecycle of other Mini-Agents or security tools within the infrastructure.
-   **Communication (Conceptual)**: Would likely interact with orchestration platforms (e.g., Kubernetes) and report status to the IA Principale.

## Developing New Agents

New agents should generally adhere to the following principles:
-   Perform a specialized cybersecurity task.
-   Communicate with the IA Principale via Kafka for tasking and reporting, using defined topics and message schemas (to be documented).
-   Be configurable via environment variables, especially for Kafka connectivity.
-   Be containerizable (Docker-friendly) for ease of deployment.
-   Refer to the existing `agent_detection` and `agent_analysis` agents for examples of Kafka integration and basic structure.

## Future Enhancements

-   Individual `README.md` files within each agent's directory, providing detailed setup, configuration, and operational instructions.
-   Standardized message schemas for Kafka topics to ensure interoperability.
-   Centralized configuration management for agents.
-   Standardized logging and metrics collection from all agents, potentially feeding into a dedicated monitoring stack.
-   Health check mechanisms for agents, reportable to the IA Principale or dashboard.

---
*This README provides an overview of the Mini Agents system. For information about the entire ZT Immune System project, refer to the main README.md in the project root.*
