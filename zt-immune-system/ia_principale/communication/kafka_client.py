import json
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

class KafkaProducerWrapper:
    def __init__(self, bootstrap_servers='localhost:9092'):
        self.bootstrap_servers = bootstrap_servers
        self.producer = None
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            print(f"KafkaProducerWrapper initialized with servers: {self.bootstrap_servers}")
        except NoBrokersAvailable:
            print(f"Error: No Kafka brokers available at {self.bootstrap_servers}. Producer not initialized.")
        except Exception as e:
            print(f"An unexpected error occurred during KafkaProducerWrapper initialization: {e}")

    def send_message(self, topic, message):
        if not self.producer:
            print("Error: Producer is not initialized. Cannot send message.")
            return False
        try:
            future = self.producer.send(topic, message)
            # Block for 'synchronous' sends
            record_metadata = future.get(timeout=10)
            print(f"Message sent to topic '{topic}' at offset {record_metadata.offset}")
            return True
        except KafkaError as ke:
            print(f"KafkaError sending message to topic '{topic}': {ke}")
        except Exception as e:
            print(f"An unexpected error occurred sending message to topic '{topic}': {e}")
        return False

    def close(self):
        if self.producer:
            self.producer.flush()
            self.producer.close()
            print("KafkaProducerWrapper closed.")

class KafkaConsumerWrapper:
    def __init__(self, topic, bootstrap_servers='localhost:9092', group_id=None):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.consumer = None
        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                auto_offset_reset='earliest' # Start reading at the earliest message if no offset is stored
            )
            print(f"KafkaConsumerWrapper initialized for topic '{self.topic}' with servers: {self.bootstrap_servers}")
        except NoBrokersAvailable:
            print(f"Error: No Kafka brokers available at {self.bootstrap_servers}. Consumer not initialized.")
        except Exception as e:
            print(f"An unexpected error occurred during KafkaConsumerWrapper initialization: {e}")

    def poll_messages(self, callback_function, timeout_ms=1000, max_messages=1):
        if not self.consumer:
            print("Error: Consumer is not initialized. Cannot poll messages.")
            return

        messages_processed = 0
        try:
            # For a finite number of messages, we loop until max_messages is reached or timeout occurs.
            # For infinite messages (max_messages = float('inf')), loop indefinitely.

            # Determine loop condition based on max_messages
            # If max_messages is finite, we use a for loop for clarity on the number of attempts.
            # If max_messages is infinite, we use a while True loop.

            if max_messages == float('inf'):
                loop_active = True
                while loop_active:
                    msg_pack = self.consumer.poll(timeout_ms=timeout_ms, max_records=1 if max_messages == 1 else None) # Fetch more if not single message
                    if not msg_pack:
                        continue # Continue polling if no messages and in infinite mode

                    for tp, messages in msg_pack.items():
                        for message in messages:
                            print(f"Received message from topic '{message.topic}': {message.value}")
                            try:
                                callback_function(message.value)
                                # In infinite mode, we don't increment messages_processed towards a limit
                            except Exception as e:
                                print(f"Error processing message with callback: {e}")
            else: # Finite max_messages
                # We attempt to poll up to max_messages times, or until messages are exhausted
                # This is a bit simplified; poll can return multiple messages.
                # A more robust way for finite messages is to count them.
                for _ in range(max_messages):
                    msg_pack = self.consumer.poll(timeout_ms=timeout_ms, max_records=max_messages - messages_processed)

                    if not msg_pack: # No messages received in this poll attempt
                        break # Exit if no messages and we are not in infinite mode

                    for tp, messages in msg_pack.items():
                        for message in messages:
                            if messages_processed < max_messages:
                                print(f"Received message from topic '{message.topic}': {message.value}")
                                try:
                                    callback_function(message.value)
                                    messages_processed += 1
                                except Exception as e:
                                    print(f"Error processing message with callback: {e}")
                            if messages_processed >= max_messages:
                                break # Break inner loop
                        if messages_processed >= max_messages:
                            break # Break outer loop (over topic partitions)
                    if messages_processed >= max_messages:
                        break # Break the for _ in range(max_messages) loop


        except KafkaError as ke:
            print(f"KafkaError polling messages from topic '{self.topic}': {ke}")
        except Exception as e:
            print(f"An unexpected error occurred polling messages from topic '{self.topic}': {e}")


    def close(self):
        if self.consumer:
            self.consumer.close()
            print("KafkaConsumerWrapper closed.")

if __name__ == '__main__':
    # Example Usage (requires Kafka broker running)
    # Note: This is a basic example. In a real application,
    # you'd likely run producer and consumer in different processes/threads.

    TEST_TOPIC = 'test-topic-py-client' # Using a more specific topic name
    KAFKA_BROKER = 'localhost:9092' # Replace if your Kafka is elsewhere

    # --- Producer Example ---
    print("\n--- Kafka Producer Example ---")
    producer_wrapper = KafkaProducerWrapper(bootstrap_servers=KAFKA_BROKER)

    if producer_wrapper.producer: # Check if producer was initialized
        # Send a couple of messages
        message1 = {'id': "msg_1_py", 'data': 'Hello Kafka from Python client!'}
        producer_wrapper.send_message(TEST_TOPIC, message1)

        message2 = {'id': "msg_2_py", 'data': 'Another message for the Python queue.'}
        producer_wrapper.send_message(TEST_TOPIC, message2)

        producer_wrapper.close()
    else:
        print("Producer not initialized, skipping send example.")

    # --- Consumer Example ---
    print("\n--- Kafka Consumer Example ---")

    def my_message_handler(msg_value):
        print(f"Callback received message: {msg_value}")
        # Add your custom logic here, e.g., processing the message content
        if 'special_instruction' in msg_value:
            print(f"Special instruction found: {msg_value['special_instruction']}")

    # Initialize consumer for the test topic
    consumer_wrapper = KafkaConsumerWrapper(TEST_TOPIC, bootstrap_servers=KAFKA_BROKER, group_id='my-py-test-group')

    if consumer_wrapper.consumer: # Check if consumer was initialized
        print(f"Polling for messages on topic '{TEST_TOPIC}' (up to 2 messages, 5s timeout for poll)...")
        # Poll for up to 2 messages.
        # poll_messages will make attempts to get 'max_messages'.
        # If fewer are available before timeout, it processes what it gets.
        consumer_wrapper.poll_messages(my_message_handler, timeout_ms=5000, max_messages=2)

        # Example of continuous polling (uncomment to test)
        # print("\nStarting continuous polling (Ctrl+C to stop)...")
        # consumer_wrapper_continuous = KafkaConsumerWrapper(TEST_TOPIC, bootstrap_servers=KAFKA_BROKER, group_id='my-py-continuous-group')
        # if consumer_wrapper_continuous.consumer:
        #     try:
        #         consumer_wrapper_continuous.poll_messages(my_message_handler, timeout_ms=1000, max_messages=float('inf'))
        #     except KeyboardInterrupt:
        #         print("Continuous polling interrupted by user.")
        #     finally:
        #         consumer_wrapper_continuous.close()
        # else:
        #     print("Continuous consumer not initialized.")

        consumer_wrapper.close() # Close the first consumer instance
    else:
        print("Consumer not initialized, skipping poll example.")

    print("\n--- Example Finished ---")
