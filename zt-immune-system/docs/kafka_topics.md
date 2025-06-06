# Kafka Topics in ZT Immune System

This document outlines the Kafka topics used for asynchronous communication between various components of the ZT Immune System, primarily between the `ia_principale` (Main AI) and the `mini_agents`.

Messages are typically JSON serialized Python dictionaries. Timestamps are generally Unix timestamps (float or integer seconds since epoch).

## Core Topics

| Topic Name               | Direction                      | Publisher(s)      | Consumer(s)        | Purpose                                                                 |
|--------------------------|--------------------------------|-------------------|--------------------|-------------------------------------------------------------------------|
| `alerts_raw`             | `mini_agents` -> `ia_principale` | Detection Agents  | `ia_principale`    | For Mini Agents to send raw security alerts or observed events to the Main AI. |
| `agent_tasks_detection`  | `ia_principale` -> `mini_agents` | `ia_principale`    | Detection Agents   | For the Main AI to send tasks/commands to Detection Agents (e.g., update rules, specific scan requests). |
| `agent_tasks_analysis`   | `ia_principale` -> `mini_agents` | `ia_principale`    | Analysis Agents    | For the Main AI to task Analysis Agents with deeper analysis of specific IOCs or events. |
| `agent_tasks_response`   | `ia_principale` -> `mini_agents` | `ia_principale`    | Response Agents    | For the Main AI to instruct Response Agents to take containment or remediation actions. |
| `agent_tasks_learning`   | `ia_principale` -> `mini_agents` | `ia_principale`    | Learning Agents    | For the Main AI to send data, feedback, or tasks to Learning Agents for model updates or distributed learning.  |
| `analysis_results`       | `mini_agents` -> `ia_principale` | Analysis Agents   | `ia_principale`    | (Conceptual) For Analysis Agents to send back the results of their analysis to the Main AI. |
| `response_status`        | `mini_agents` -> `ia_principale` | Response Agents   | `ia_principale`    | (Conceptual) For Response Agents to report the status (success/failure) of executed actions. |

## Message Structures

Below are the general Python dictionary structures for messages on these topics. These are typically serialized to JSON when sent over Kafka.

### 1. `alerts_raw`

*   **Direction**: `DetectionAgent` (and potentially other agents) -> `ia_principale`
*   **Purpose**: To report raw security alerts, observed events, or notable system activities.
*   **Message Structure Example (from DetectionAgent)**:
    ```json
    {
        "agent_id": "string (e.g., agent_det_001)",
        "timestamp": "float (Unix timestamp, e.g., 1678886400.123)",
        "alert_type": "string (e.g., 'detection_event', 'health_check', 'metric_report')",
        "data": {
            // Content varies based on the alert_type.
            // For a 'detection_event' from a DetectionAgent:
            "description": "string (Mandatory, human-readable description of the alert)",
            "severity": "string (Optional, e.g., 'Low', 'Medium', 'High', 'Critical')",
            "source_ip": "string (Optional, source IP address related to the event)",
            "source_host": "string (Optional, source hostname)",
            "destination_ip": "string (Optional, destination IP address)",
            "destination_port": "integer (Optional, destination port)",
            "protocol": "string (Optional, e.g., 'TCP', 'UDP', 'ICMP')",
            "process_id": "integer (Optional, Process ID if applicable)",
            "process_name": "string (Optional, Process name if applicable)",
            "process_path": "string (Optional, Full path to the process executable)",
            "command_line": "string (Optional, Command line of the process)",
            "file_hash_md5": "string (Optional, MD5 hash of a related file)",
            "file_hash_sha256": "string (Optional, SHA256 hash of a related file)",
            "url": "string (Optional, URL related to the event)",
            "domain_name": "string (Optional, Domain name related to the event)",
            "user_agent": "string (Optional, User agent string)",
            "yara_rule_name": "string (Optional, Name of the matched YARA rule)",
            "sigma_rule_title": "string (Optional, Title of the matched Sigma rule)",
            "sigma_rule_id": "string (Optional, ID of the matched Sigma rule)",
            "triggering_keyword": "string (Optional, Specific keyword that triggered a rule)",
            "raw_log_snippet": "string (Optional, A snippet of the raw log that generated the alert)",
            "tags": ["string (Optional, list of tags, e.g., 'malware', 'c2_communication', 'data_exfiltration')"],
            "details": {
                // Agent-specific or event-specific structured details
            }
        }
    }
    ```

### 2. `agent_tasks_detection`

*   **Direction**: `ia_principale` -> `DetectionAgent`
*   **Purpose**: To send configuration updates, new detection rules, or on-demand scan requests to Detection Agents.
*   **Message Structure Example**:
    ```json
    {
        "task_id": "string (Unique ID for tracking, e.g., uuidv4)",
        "agent_type": "detection", // Target agent type
        "command": "string (e.g., 'update_rules', 'scan_directory', 'monitor_process')",
        "parameters": {
            "rules_url": "string (Optional, URL to fetch new YARA/Sigma rules from)",
            "rules_content": "string (Optional, Base64 encoded rules content)",
            "directory_to_scan": "string (Optional, for 'scan_directory' command)",
            "process_name_to_monitor": "string (Optional, for 'monitor_process' command)"
            // ... other parameters relevant to the command
        },
        "timestamp": "float (Unix timestamp)"
    }
    ```

### 3. `agent_tasks_analysis`

*   **Direction**: `ia_principale` -> `AnalysisAgent`
*   **Purpose**: To request in-depth analysis of a specific artifact (file, URL, IOC) or event.
*   **Message Structure Example**:
    ```json
    {
        "task_id": "string (Unique task ID)",
        "agent_type": "analysis", // Target agent type
        "threat_info": { // Duplicates structure from Orchestrator's dispatch_agent
            "ioc": {
                "type": "string (e.g., 'file_hash_sha256', 'url', 'domain_name', 'ip_address')",
                "value": "string (The actual IOC value)",
                "file_url": "string (Optional, URL to download the file if type is file_hash)"
                // ... other relevant metadata about the IOC
            },
            "depth": "string (e.g., 'quick', 'standard', 'deep', 'forensic')",
            "analysis_profile": "string (Optional, e.g., 'windows_malware', 'linux_exploit', 'phishing_url')",
            "related_alerts": ["string (Optional, list of alert IDs that triggered this analysis)"]
        },
        "timestamp": "float (Unix timestamp)"
    }
    ```

### 4. `agent_tasks_response`

*   **Direction**: `ia_principale` -> `ResponseAgent`
*   **Purpose**: To instruct Response Agents to execute specific containment or remediation actions.
*   **Message Structure Example**:
    ```json
    {
        "task_id": "string (Unique task ID)",
        "agent_type": "response", // Target agent type
        "threat_info": { // Duplicates structure from Orchestrator's dispatch_agent
            "ioc": {
                "type": "string (e.g., 'ip_address', 'domain_name', 'user_account')",
                "value": "string (The entity to act upon)"
            },
            "action": "string (e.g., 'block_ip', 'isolate_host', 'disable_user', 'quarantine_file')",
            "target_node": "string (Optional, specific host/device ID to apply action if not implied by IOC)",
            "duration_seconds": "integer (Optional, duration for temporary actions like blocking an IP)"
        },
        "timestamp": "float (Unix timestamp)"
    }
    ```

### 5. `agent_tasks_learning`

*   **Direction**: `ia_principale` -> `LearningAgent`
*   **Purpose**: To send data or instructions to Learning Agents for model training, updates, or feedback processing.
*   **Message Structure Example**:
    ```json
    {
        "task_id": "string (Unique task ID)",
        "agent_type": "learning", // Target agent type
        "command": "string (e.g., 'process_feedback', 'retrain_model_segment', 'collect_features')",
        "parameters": {
            "event_data": { // (Optional) Original event data for context
                // ... structure of the original event from alerts_raw or enriched data
            },
            "classification_feedback": { // (Optional) Analyst feedback on an event
                "event_id": "string",
                "analyst_classification": "string (e.g., 'true_positive_critical', 'false_positive', 'benign')",
                "confidence": "float (0.0-1.0)",
                "comments": "string"
            },
            "model_segment_id": "string (Optional, if retraining a specific part of a model)",
            "new_data_url": "string (Optional, URL to a dataset for training/learning)"
        },
        "timestamp": "float (Unix timestamp)"
    }
    ```

---
*This document is a living specification and may evolve as the ZT Immune System develops. Ensure components adhere to the latest agreed-upon structures.*
