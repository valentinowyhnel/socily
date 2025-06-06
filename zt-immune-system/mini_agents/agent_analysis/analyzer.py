import time
import signal
import sys
import json
import os # For environment variable access
# Assuming PYTHONPATH is set up to find ia_principale, or this agent is run in an environment
# where ia_principale is discoverable. If not, this import will fail.
# For a more robust solution, consider packaging ia_principale or using relative imports
# if the directory structure allows and it's part of the same package.
try:
    from ia_principale.communication.kafka_client import KafkaConsumerWrapper
except ImportError:
    # Fallback for environments where ia_principale might not be in PYTHONPATH directly
    # This is a common issue in complex project structures.
    # A better solution involves proper packaging or PYTHONPATH manipulation.
    print("Error: Could not import KafkaConsumerWrapper from ia_principale.communication.kafka_client.")
    print("Ensure that the 'ia_principale' directory is in your PYTHONPATH or installed as a package.")
    print("Using a placeholder consumer for now if KafkaConsumerWrapper is not found.")
    # Define a placeholder if the import fails, to allow basic script structure testing
    class KafkaConsumerWrapper: # Renamed to avoid potential silent override if real one is on path
        def __init__(self, topic, bootstrap_servers, group_id):
            print(f"PlaceholderKafkaConsumer: topic={topic}, servers={bootstrap_servers}, group_id={group_id}")
            self.consumer = None # Simulate no active consumer; real consumer would be an object
            self.is_placeholder = True

        def poll_messages(self, callback, timeout_ms, max_messages):
            print(f"PlaceholderKafkaConsumer: Would poll {max_messages} from Kafka with timeout {timeout_ms}ms and call {callback.__name__}")
            # time.sleep(timeout_ms / 1000) # Simulate blocking
        def close(self):
            print("PlaceholderKafkaConsumer: Closed.")

# Global Variables/Constants
AGENT_ID = "analysis_agent_001"
KAFKA_BROKER_ADDRESS = os.environ.get("KAFKA_BROKER_ADDRESS", "localhost:9092")
TASKS_TOPIC = "agent_tasks_analysis"
CONSUMER_GROUP_ID = "analysis_agents_group_1"

consumer_instance = None  # Global variable to hold the consumer instance for signal handling
stop_processing_flag = False  # Global flag for graceful shutdown

def signal_handler(sig, frame):
    """Handles SIGINT and SIGTERM for graceful shutdown."""
    global stop_processing_flag
    print(f"\n[{AGENT_ID}] Signal {signal.Signals(sig).name} received, preparing to shut down...")
    stop_processing_flag = True

def on_task_received_callback(task_data):
    """Callback function to process tasks received from Kafka."""
    print(f"[{AGENT_ID}] Task received via Kafka: {json.dumps(task_data, indent=2)}")
    # Placeholder for actual analysis logic
    # Example:
    # if task_data.get("agent_type") == "analysis":
    #     ioc_to_analyze = task_data.get("threat_info", {}).get("ioc", {}).get("value")
    #     if ioc_to_analyze:
    #         print(f"[{AGENT_ID}] Analyzing IOC: {ioc_to_analyze}...")
    #         time.sleep(random.randint(2,5)) # Simulate analysis work
    #         print(f"[{AGENT_ID}] Analysis complete for IOC: {ioc_to_analyze}. Result: (simulated_details)")
    #     else:
    #         print(f"[{AGENT_ID}] No IOC value found in task: {task_data.get('task_id', 'N/A')}")
    # else:
    #     print(f"[{AGENT_ID}] Received task not for analysis agent or malformed: {task_data.get('task_id', 'N/A')}")

    print(f"[{AGENT_ID}] Finished processing (simulated) for task: {task_data.get('task_id', task_data.get('threat_info', {}).get('ioc', {}).get('value', 'N/A'))}")
    time.sleep(1) # Simulate some work being done

def run_analyzer():
    """Main function to run the analysis agent."""
    global consumer_instance, stop_processing_flag

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"[{AGENT_ID}] Initializing Kafka consumer for topic '{TASKS_TOPIC}' at {KAFKA_BROKER_ADDRESS} with group ID '{CONSUMER_GROUP_ID}'")
    # KafkaConsumerWrapper expects (topic, bootstrap_servers, group_id)
    consumer_instance = KafkaConsumerWrapper(TASKS_TOPIC, KAFKA_BROKER_ADDRESS, CONSUMER_GROUP_ID)

    # Check if the consumer is the placeholder or a real one that failed to initialize its internal consumer
    is_real_consumer_active = hasattr(consumer_instance, 'is_placeholder') and not consumer_instance.is_placeholder and consumer_instance.consumer is not None
    is_placeholder_consumer = hasattr(consumer_instance, 'is_placeholder') and consumer_instance.is_placeholder

    if not (is_real_consumer_active or is_placeholder_consumer):
        print(f"[{AGENT_ID}] Failed to initialize Kafka consumer (actual Kafka library consumer object is None and it's not the placeholder).")
        print(f"[{AGENT_ID}] This might be due to Kafka server unavailability or incorrect kafka-python setup.")
        print(f"[{AGENT_ID}] Exiting agent.")
        return

    if is_placeholder_consumer:
        print(f"[{AGENT_ID}] WARNING: Running with Placeholder Kafka Consumer. No actual Kafka communication will occur.")

    print(f"[{AGENT_ID}] Analysis Agent started. Waiting for tasks on topic '{TASKS_TOPIC}'. Press Ctrl+C to stop.")

    try:
        while not stop_processing_flag:
            active_consumer_exists = hasattr(consumer_instance, 'consumer') and consumer_instance.consumer is not None
            is_placeholder = hasattr(consumer_instance, 'is_placeholder') and consumer_instance.is_placeholder

            if active_consumer_exists or is_placeholder:
                consumer_instance.poll_messages(on_task_received_callback, timeout_ms=1000, max_messages=5)
                if is_placeholder and not stop_processing_flag: # Placeholder needs explicit sleep if poll_messages is non-blocking
                    time.sleep(1)
            else:
                print(f"[{AGENT_ID}] Kafka consumer not available or not properly initialized. Retrying in 5s...")
                time.sleep(5)
                if stop_processing_flag:
                    break
                consumer_instance = KafkaConsumerWrapper(TASKS_TOPIC, KAFKA_BROKER_ADDRESS, CONSUMER_GROUP_ID)
                # Re-check after attempting re-initialization
                active_consumer_exists = hasattr(consumer_instance, 'consumer') and consumer_instance.consumer is not None
                is_placeholder = hasattr(consumer_instance, 'is_placeholder') and consumer_instance.is_placeholder
                if not (active_consumer_exists or is_placeholder):
                    print(f"[{AGENT_ID}] Failed to reconnect/re-initialize Kafka consumer. Exiting loop.")
                    break

        print(f"\n[{AGENT_ID}] Stop signal processed or loop deliberately exited. Preparing to close consumer.")
    except Exception as e:
        print(f"[{AGENT_ID}] An unexpected error occurred in the main loop: {e}")
    finally:
        if consumer_instance:
            print(f"[{AGENT_ID}] Closing Kafka consumer...")
            consumer_instance.close()
        print(f"[{AGENT_ID}] Shutdown complete.")

if __name__ == "__main__":
    run_analyzer()
