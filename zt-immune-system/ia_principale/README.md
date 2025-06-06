# ZT Immune System - IA Principale (Main AI)


![Gemini_Generated_Image_jp9akvjp9akvjp9a](https://github.com/user-attachments/assets/20085505-158d-4184-bf0a-f6ac259964e5)



## Overview

The IA Principale (Main AI) is the central intelligence and orchestration hub of the ZT Immune System. It acts as the "brain" of the platform, responsible for:

-   Receiving and ingesting security alerts and events from various Mini-Agents via Kafka.
-   Analyzing and correlating these events to identify and evaluate potential threats.
-   Making decisions based on threat levels, system policies, and learned behaviors.
-   Orchestrating responses by dispatching tasks to appropriate Mini-Agents (e.g., for deeper analysis, containment, remediation, or further data collection for learning).
-   Continuously learning and adapting from new data and the outcomes of its decisions (future capability).

Key sub-modules within the IA Principale include:
-   **`Orchestrator`**: The core component that processes events, evaluates threats, and decides on actions.
-   **`DataIngestion`**: Currently, this module includes the Kafka consumer logic for the `alerts_raw` topic, feeding data into the Orchestrator.
-   **`ThreatAnalyzer`**: (Conceptual) Would contain more sophisticated threat analysis logic, potentially including correlation engines and connections to threat intelligence feeds.
-   **`KafkaClient`**: Wrappers for Kafka producer and consumer functionalities, facilitating communication.

## Technologies Used

-   **Python 3.9+**: The primary programming language.
-   **`kafka-python`**: Python client for Apache Kafka, used for all message bus interactions.
-   **Various data processing and AI/ML libraries**: As the system evolves, this will include libraries such as:
    -   `pandas`, `numpy` (for data manipulation - placeholder)
    -   `scikit-learn` (for classical machine learning models - placeholder)
    -   `TensorFlow` / `PyTorch` (for deep learning models - placeholder)
    -   Other specialized libraries for NLP, anomaly detection, etc.

## Prerequisites

-   **Python**: Version 3.9 or newer is recommended.
-   **`pip`**: The Python package installer.
-   **Virtual Environment (Recommended)**: To manage project dependencies.
-   **Running Kafka Broker**: A running instance of Apache Kafka (e.g., v2.x or 3.x) is essential as all primary inputs and outputs of the IA Principale are via Kafka topics.

## Project Setup and Installation

1.  **Navigate to the Main AI directory**:
    ```bash
    cd zt-immune-system/ia_principale
    ```

2.  **Create and activate a Python virtual environment**:
    ```bash
    python -m venv venv
    ```
    Activate the environment:
    -   Linux/macOS: `source venv/bin/activate`
    -   Windows: `venv\Scripts\activate`

3.  **Install dependencies**:
    *A dedicated `requirements.txt` file within this `ia_principale` directory is highly recommended.* If it exists, run:
    ```bash
    pip install -r requirements.txt
    ```
    If a dedicated `requirements.txt` is not present, ensure dependencies are installed from the main project `requirements.txt` (located at `zt-immune-system/requirements.txt`). Currently, the main project `requirements.txt` only lists `kafka-python`. Other libraries like data processing or ML libraries would need to be added either here or in the main file.

    Example of manual installation if needed:
    ```bash
    pip install kafka-python pandas scikit-learn # Add other necessary libraries
    ```

## Configuration

Configuration is primarily managed through environment variables.

-   **Key Environment Variables**:
    -   **`KAFKA_BROKER_ADDRESS`**: Crucial for operation. Specifies the address(es) of the Kafka broker(s).
        -   Default: `"localhost:9092"` (if not set, as per component defaults).
        -   Example: `export KAFKA_BROKER_ADDRESS="kafka1:9093,kafka2:9093"`

-   **Kafka Topics**:
    The IA Principale interacts with the following Kafka topics:
    -   **Consumes from**:
        -   `alerts_raw`: For receiving raw security alerts and events from detection agents and other sources.
    -   **Publishes to (via Orchestrator)**:
        -   `agent_tasks_analysis`: To dispatch tasks for detailed analysis to `agent_analysis` instances.
        -   `agent_tasks_detection`: (Future) For configuring or tasking `agent_detection` instances.
        -   `agent_tasks_response`: (Future) For dispatching response actions to `agent_response` instances.
        -   `agent_tasks_learning`: (Future) For tasks related to distributed learning or data gathering for `agent_learning` instances.

## Running the Main AI

1.  **Ensure Kafka is Running**: Verify that your Apache Kafka broker is operational and accessible.
2.  **Set Environment Variables**: Make sure the `KAFKA_BROKER_ADDRESS` environment variable is set correctly in your shell or environment configuration system.
    ```bash
    export KAFKA_BROKER_ADDRESS="localhost:9092" # Example for Linux/macOS
    # For Windows (cmd): set KAFKA_BROKER_ADDRESS=localhost:9092
    # For Windows (PowerShell): $env:KAFKA_BROKER_ADDRESS="localhost:9092"
    ```
3.  **Activate Virtual Environment**:
    ```bash
    # (If not already active)
    cd zt-immune-system/ia_principale
    source venv/bin/activate
    ```
4.  **Run the Main Application**:
    ```bash
    python main.py
    ```
    This will start the IA Principale, which typically includes initializing the Kafka consumer for alerts (via `data_ingestion.py`) and preparing the Orchestrator.

## Key Modules & Logic Flow

-   **`main.py`**:
    -   The main entry point for the IA Principale application.
    -   Initializes the `Orchestrator`.
    -   Starts the Kafka consumer thread (via `data_ingestion.start_alerts_raw_consumer`) to listen for messages on the `alerts_raw` topic.
    -   Handles graceful shutdown of components (e.g., closing the Orchestrator's Kafka producer and stopping the consumer thread).
-   **`orchestrator.py`**:
    -   Contains the `Orchestrator` class, which is the core decision-making and task-dispatching engine.
    -   `process_event()`: Receives event data (typically from the Kafka consumer), evaluates threat levels, and decides on appropriate actions.
    -   `dispatch_agent()`: Sends tasks/commands to specific Mini-Agent types via their designated Kafka topics using its internal Kafka producer.
-   **`data_ingestion.py`**:
    -   `start_alerts_raw_consumer()`: This function runs in a separate thread (started by `main.py`). It initializes a `KafkaConsumerWrapper` to consume messages from the `alerts_raw` topic.
    -   Received messages are passed to the `orchestrator_instance.process_event()` method for handling.
-   **`communication/kafka_client.py`**:
    -   Provides `KafkaProducerWrapper` and `KafkaConsumerWrapper` classes. These are general-purpose wrappers around the `kafka-python` library to simplify producing and consuming JSON messages to/from Kafka topics.
-   **`threat_analysis.py` (Conceptual / Placeholder)**:
    -   This module would be responsible for more advanced threat analysis logic, such as event correlation, IOC enrichment, and risk scoring. The `Orchestrator` would likely call functions from this module.
-   **`nlp_module.py` (Conceptual / Placeholder)**:
    -   If the system needs to process unstructured text data (e.g., from logs or threat reports), this module would contain Natural Language Processing capabilities.
-   **`ml_learning.py` (Conceptual / Placeholder)**:
    -   This module would house the machine learning models, training pipelines, and prediction functions used by the IA Principale.

## Directory Structure

A brief overview of the key directories and files within `ia_principale/`:

-   **`communication/`**:
    -   `kafka_client.py`: Contains the Kafka producer and consumer wrapper classes.
-   **`event_processing/` (Conceptual - current logic in `orchestrator.py`)**:
    -   Would contain more detailed event parsing, normalization, and enrichment logic.
-   **`models/` (Conceptual)**:
    -   Could store Pydantic models for data structures, or serialized machine learning models.
-   **`main.py`**: Main application entry point.
-   **`orchestrator.py`**: Core orchestration logic.
-   **`data_ingestion.py`**: Kafka alert consumer setup.
-   **`requirements.txt` (Recommended)**: Should list Python dependencies specific to `ia_principale`.
-   **`README.md`**: This file.

---
*This README provides an overview specific to the IA Principale. For information about the entire ZT Immune System project, refer to the main README.md in the project root.*
