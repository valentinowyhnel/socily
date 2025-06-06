# zt-immune-system/ia_principale/communication/kafka_client.py
"""
Kafka client wrappers for producing and consuming messages using the kafka-python library.

This module provides:
- `KafkaProducerWrapper`: A class to simplify sending JSON messages to Kafka topics.
  It handles serialization to JSON and UTF-8 encoding. Includes basic retry logic
  and waits for acknowledgements from all in-sync replicas by default.
- `KafkaConsumerWrapper`: A class to simplify consuming JSON messages from Kafka topics.
  It handles deserialization from JSON and UTF-8 decoding. Supports consumer groups
  and configurable auto offset reset behavior.

Both wrappers include logging for important events and error conditions.
"""

import json
import logging
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

# Configure logger for this module
logger = logging.getLogger(__name__)
# BasicConfig is usually set up in the main entry point (e.g., main.py).
# This conditional setup is for standalone testing or use of this module.
if not logger.hasHandlers() and not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
    )

class KafkaProducerWrapper:
    """
    A wrapper around kafka.KafkaProducer for sending JSON messages.

    Handles JSON serialization and provides basic configuration for reliability.
    """
    def __init__(self, bootstrap_servers: str = 'localhost:9092'):
        """
        Initializes the KafkaProducerWrapper.

        Args:
            bootstrap_servers: Comma-separated string of Kafka broker addresses
                               (e.g., 'host1:port1,host2:port2').
        """
        self.bootstrap_servers = bootstrap_servers
        self.producer: Optional[KafkaProducer] = None
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                # Common configurations for improved reliability:
                retries=3,          # Number of times to retry sending a message on failure.
                linger_ms=100,      # Max time (ms) to batch messages before sending.
                acks='all',         # Wait for acknowledgements from all in-sync replicas.
                # request_timeout_ms=30000 # Optional: Timeout for individual requests.
            )
            logger.info(f"KafkaProducerWrapper initialized successfully for servers: {self.bootstrap_servers}")
        except NoBrokersAvailable:
            logger.error(
                f"No Kafka brokers available at {self.bootstrap_servers}. "
                "KafkaProducerWrapper initialization failed. Messages cannot be sent."
            )
        except Exception: # Catch any other unexpected errors during initialization
            logger.exception(
                f"An unexpected error occurred during KafkaProducerWrapper initialization "
                f"for servers {self.bootstrap_servers}."
            )

    def send_message(self, topic: str, message: Any) -> bool:
        """
        Sends a message to the specified Kafka topic.

        The message will be JSON serialized.

        Args:
            topic: The Kafka topic to send the message to.
            message: The message payload (should be JSON serializable).

        Returns:
            True if the message was sent and acknowledged successfully, False otherwise.
        """
        if not self.producer:
            logger.error(
                f"KafkaProducer is not initialized. Cannot send message to topic '{topic}'. "
                "Ensure Kafka brokers are available and producer initialized correctly."
            )
            return False
        try:
            # The send operation is asynchronous. future.get() makes it synchronous for confirmation.
            future = self.producer.send(topic, message)
            # Block for 'synchronous' confirmation with a timeout.
            record_metadata = future.get(timeout=10) # Timeout in seconds
            logger.info(
                f"Message successfully sent to Kafka topic '{topic}', "
                f"partition {record_metadata.partition}, offset {record_metadata.offset}."
            )
            return True
        except KafkaError: # Specific Kafka errors (e.g., timeout, broker not available during send)
            logger.exception(f"KafkaError occurred while sending message to topic '{topic}'. Message: {message}")
        except Exception: # Other unexpected errors (e.g., serialization issues if not caught by serializer)
            logger.exception(f"An unexpected error occurred while sending message to topic '{topic}'. Message: {message}")
        return False

    def close(self):
        """
        Flushes any buffered messages and closes the Kafka producer.

        It's important to call this method when the producer is no longer needed
        to ensure all messages are sent and resources are released.
        """
        if self.producer:
            logger.info("Attempting to flush and close KafkaProducerWrapper...")
            try:
                self.producer.flush(timeout=10) # Attempt to send any buffered messages with timeout
                logger.debug("KafkaProducer flushed successfully.")
            except KafkaError:
                logger.exception("KafkaError occurred during KafkaProducer flush.")
            except Exception: # Catch other flush errors
                logger.exception("Unexpected error occurred during KafkaProducer flush.")
            finally:
                try:
                    self.producer.close(timeout=10) # Close producer with timeout
                    logger.info("KafkaProducerWrapper closed successfully.")
                except KafkaError:
                    logger.exception("KafkaError occurred during KafkaProducer close.")
                except Exception:
                    logger.exception("Unexpected error occurred during KafkaProducer close.")
        else:
            logger.info("KafkaProducerWrapper was not initialized or already closed. No action taken.")


class KafkaConsumerWrapper:
    """
    A wrapper around kafka.KafkaConsumer for consuming JSON messages.

    Handles JSON deserialization and provides configuration for consumer group behavior.
    """
    def __init__(self, topic: str, bootstrap_servers: str = 'localhost:9092', group_id: Optional[str] = None, auto_offset_reset: str = 'earliest'):
        """
        Initializes the KafkaConsumerWrapper.

        Args:
            topic: The Kafka topic to subscribe to.
            bootstrap_servers: Comma-separated string of Kafka broker addresses.
            group_id: The consumer group ID. If None, the consumer operates as a simple
                      consumer (not part of a group, typically for unique consumption or testing).
            auto_offset_reset: Policy for where to begin reading messages if no offset is
                               committed for the group, or if an offset is out of range.
                               Common values: 'earliest', 'latest'.
        """
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self.consumer: Optional[KafkaConsumer] = None
        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                auto_offset_reset=self.auto_offset_reset,
                enable_auto_commit=True,         # Commits offsets automatically in the background.
                auto_commit_interval_ms=5000,    # Interval (ms) for auto-committing offsets.
                # consumer_timeout_ms=1000       # Optional: if you want poll to block for a max time
                                                 # then raise an error if no messages. Often preferred to
                                                 # handle this in the poll loop itself with poll(timeout_ms).
            )
            logger.info(
                f"KafkaConsumerWrapper initialized for topic '{self.topic}', group_id '{self.group_id}' "
                f"with servers: {self.bootstrap_servers}"
            )
        except NoBrokersAvailable:
            logger.error(
                f"No Kafka brokers available at {self.bootstrap_servers}. "
                f"KafkaConsumerWrapper for topic '{self.topic}' initialization failed."
            )
        except Exception:
            logger.exception(
                f"An unexpected error occurred during KafkaConsumerWrapper initialization "
                f"for topic '{self.topic}'."
            )

    def poll_messages(self, callback_function: callable, timeout_ms: int = 1000, max_messages_to_process_per_poll: Optional[int] = None) -> bool:
        """
        Polls messages from Kafka and processes them using the provided callback_function.

        This method is designed to be called within a loop for continuous message consumption.
        It handles one batch of messages per call. The calling code should manage the loop
        and any stop conditions.

        Args:
            callback_function: A function to call for each received message.
                               It will be passed the deserialized message value.
            timeout_ms: The time (in milliseconds) for the poll() call to block waiting for messages.
                        A value of 0 makes it non-blocking.
            max_messages_to_process_per_poll: Maximum number of messages to fetch from a single
                                              poll() call. If None, processes all messages
                                              returned by the underlying consumer's poll.

        Returns:
            True if polling was successful (even if no messages were received),
            False if an error occurred during polling that prevented message retrieval.
        """
        if not self.consumer:
            logger.error(
                f"KafkaConsumer for topic '{self.topic}' is not initialized. Cannot poll messages."
            )
            return False

        try:
            # consumer.poll() returns a dictionary of {TopicPartition: [messages]}
            msg_pack = self.consumer.poll(timeout_ms=timeout_ms, max_records=max_messages_to_process_per_poll)

            if not msg_pack: # No messages received in this poll interval
                return True # Polling itself was successful, just no new messages

            for tp, messages in msg_pack.items():
                logger.debug(f"Processing {len(messages)} messages from Kafka topic '{tp.topic}' partition {tp.partition}")
                for message in messages:
                    # message.value is already deserialized by the consumer's value_deserializer
                    logger.debug(f"Received raw message from topic '{message.topic}': {message.value}")
                    try:
                        callback_function(message.value)
                    except Exception:
                        logger.exception(
                            f"Error processing message with callback for topic '{message.topic}'. "
                            f"Message value: {message.value}"
                        )
            return True # Polling and processing of received messages (if any) was successful
        except KafkaError: # Errors related to Kafka communication during poll
            logger.exception(f"KafkaError occurred while polling messages from topic '{self.topic}'.")
        except Exception: # Other unexpected errors during polling
            logger.exception(f"An unexpected error occurred while polling messages from topic '{self.topic}'.")
        return False # Indicate that polling failed due to an error

    def close(self):
        """
        Closes the Kafka consumer.

        It's important to call this to release resources and ensure proper consumer group
        rebalancing if applicable.
        """
        if self.consumer:
            logger.info(f"Attempting to close KafkaConsumerWrapper for topic '{self.topic}', group_id '{self.group_id}'...")
            try:
                self.consumer.close()
                logger.info(f"KafkaConsumerWrapper for topic '{self.topic}', group_id '{self.group_id}' closed successfully.")
            except Exception: # KafkaConsumer.close() can sometimes raise errors
                logger.exception(f"Error occurred while closing KafkaConsumerWrapper for topic '{self.topic}'.")
        else:
            logger.info(f"KafkaConsumerWrapper for topic '{self.topic}' was not initialized or already closed. No action taken.")


if __name__ == '__main__':
    # This __main__ block is for example usage/testing.
    # It uses its own logger setup for clarity when run directly.
    main_logger = logging.getLogger(__name__ + ".main_example")
    if not main_logger.hasHandlers() and not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    main_logger.info("Kafka client direct execution example started.")

    TEST_TOPIC = 'test-topic-py-client-logging-docs' # New topic for this test run
    KAFKA_BROKER = 'localhost:9092' # Ensure Kafka is running here for the example

    # --- Producer Example ---
    main_logger.info("\n--- Kafka Producer Example ---")
    producer_wrapper = KafkaProducerWrapper(bootstrap_servers=KAFKA_BROKER)

    if producer_wrapper.producer:
        main_logger.info("Producer seems initialized. Sending messages...")
        msg1_data = {'id': "msg_1_py_log_doc", 'data': 'Hello Kafka from Python client with updated docs!'}
        producer_wrapper.send_message(TEST_TOPIC, msg1_data)

        msg2_data = {'id': "msg_2_py_log_doc", 'data': 'Another message for the Python queue with updated docs.'}
        producer_wrapper.send_message(TEST_TOPIC, msg2_data)

        producer_wrapper.close()
    else:
        main_logger.warning("Producer was not initialized successfully. Skipping send example.")

    # --- Consumer Example ---
    main_logger.info("\n--- Kafka Consumer Example ---")

    received_message_count = 0
    def my_message_handler(msg_value: Any):
        nonlocal received_message_count
        main_logger.info(f"Callback received message: {msg_value}")
        received_message_count += 1
        if 'special_instruction' in msg_value: # Example of conditional logic
            main_logger.info(f"Special instruction found in message: {msg_value['special_instruction']}")

    # Use a unique group_id for testing to ensure it reads from the beginning or as per policy
    consumer_group_id = 'my-py-test-group-logging-docs'
    consumer_wrapper = KafkaConsumerWrapper(
        TEST_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        group_id=consumer_group_id,
        auto_offset_reset='earliest' # Ensure it reads from the start for this test
    )

    if consumer_wrapper.consumer:
        main_logger.info(f"Polling for messages on topic '{TEST_TOPIC}' (will attempt a few polls)...")
        import time # Import time for time.sleep()

        # Poll for a short period to try and get the messages sent by the producer
        for i in range(10): # Try to poll multiple times to allow consumer to catch up
            if received_message_count >= 2: # Stop if we've received the two messages sent
                break
            main_logger.debug(f"Poll attempt {i+1}")
            # The poll_messages method is designed to be called in a loop.
            # It processes one batch of messages per call.
            success = consumer_wrapper.poll_messages(
                my_message_handler,
                timeout_ms=1000, # Block for up to 1 second
                max_messages_to_process_per_poll=5 # Process up to 5 messages from this poll
            )
            if not success:
                 main_logger.warning("Polling call returned False, indicating an issue. Check logs.")
                 # Depending on the error, may want to break or retry with backoff
            if i < 9 and received_message_count < 2 : # Avoid sleeping on the last iteration or if done
                 time.sleep(0.5) # Wait a bit between polls if messages not yet received

        main_logger.info(f"Finished polling attempts. Total messages received by callback: {received_message_count}")
        consumer_wrapper.close()
    else:
        main_logger.warning("Consumer was not initialized successfully. Skipping poll example.")

    main_logger.info("\n--- Kafka client direct execution example finished. ---")
