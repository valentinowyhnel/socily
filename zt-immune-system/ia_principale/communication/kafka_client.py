# /zt-immune-system/ia_principale/communication/kafka_client.py
# Simulates Kafka client functionalities (Producer and Consumer)
# In a real application, you would use a library like 'kafka-python' or 'confluent-kafka-python'.

import json
import time
import random # For simulation

print("Initialisation du logger pour Kafka Client (kafka_client.py) (placeholder)")

# --- Configuration (Conceptual - would be loaded from a config file or env vars) ---
KAFKA_BOOTSTRAP_SERVERS = ['kafka_server1:9092', 'kafka_server2:9092'] # Placeholder

# --- Kafka Producer Simulation ---

class SimulatedKafkaException(Exception):
    """Custom exception for simulated Kafka errors."""
    pass

class SimulatedKafkaProducer:
    def __init__(self, bootstrap_servers=None, value_serializer=None, retries=3, **kwargs):
        self.bootstrap_servers = bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        self.value_serializer = value_serializer or (lambda v: json.dumps(v).encode('utf-8'))
        self.retries = retries
        self.connected = False
        self._connect()
        print(f"SimulatedKafkaProducer initialisé. Serveurs: {self.bootstrap_servers}, Serializer: {'JSON Lambda' if self.value_serializer else 'None'}")

    def _connect(self):
        print(f"  SimulatedKafkaProducer: Tentative de connexion à {self.bootstrap_servers}...")
        if random.random() < 0.05: # 5% chance of connection failure
            print("  SimulatedKafkaProducer: Échec de la connexion (simulé).")
            self.connected = False
        else:
            print("  SimulatedKafkaProducer: Connecté avec succès (simulé).")
            self.connected = True
    
    def send(self, topic, value=None, key=None, headers=None, partition=None, timestamp_ms=None):
        if not self.connected:
            print("  SimulatedKafkaProducer: Non connecté. Tentative de reconnexion...")
            self._connect()
            if not self.connected:
                print("  SimulatedKafkaProducer: Échec de la reconnexion. Message non envoyé.")
                # Create a future that will immediately fail
                future = SimulatedKafkaFuture(topic, partition if partition is not None else 0, value)
                future._set_result(success=False, exception=SimulatedKafkaException("Échec de l'envoi: Producteur non connecté et reconnexion échouée."))
                return future

        serialized_value = self.value_serializer(value) if self.value_serializer and value is not None else value
        
        for attempt in range(self.retries + 1):
            if random.random() < 0.1 and attempt < self.retries : 
                print(f"  SimulatedKafkaProducer: Échec de l'envoi (tentative {attempt + 1}/{self.retries +1}) pour le topic '{topic}' (simulé). Nouvelle tentative...")
                time.sleep(0.01) 
                if attempt == self.retries -1: 
                    print(f"  SimulatedKafkaProducer: Échec de l'envoi du message au topic '{topic}' après {self.retries} tentatives (simulé).")
                    future = SimulatedKafkaFuture(topic, partition if partition is not None else 0, value)
                    future._set_result(success=False, exception=SimulatedKafkaException(f"Échec de l'envoi au topic '{topic}' après {self.retries} tentatives."))
                    return future
                continue

            print(f"  SimulatedKafkaProducer: Message envoyé au topic '{topic}'.")
            # Ensure serialized_value is not bytes for the print, or decode if it is
            sv_str = serialized_value.decode('utf-8') if isinstance(serialized_value, bytes) else str(serialized_value)
            print(f"    Clé: {key}, Valeur (sérialisée): {sv_str[:100] if sv_str else 'None'}...")
            
            future = SimulatedKafkaFuture(topic, partition if partition is not None else 0, value)
            future._set_result(success=True, offset=random.randint(1000, 2000))
            return future
        
        # Fallback, should ideally be covered by the loop logic
        final_failure_future = SimulatedKafkaFuture(topic, partition if partition is not None else 0, value)
        final_failure_future._set_result(success=False, exception=SimulatedKafkaException(f"Échec de l'envoi au topic '{topic}' après {self.retries} tentatives (fallback)."))
        return final_failure_future


    def flush(self, timeout=None):
        print("  SimulatedKafkaProducer: flush() appelé. (simulé).")
        return True

    def close(self, timeout=None):
        print("  SimulatedKafkaProducer: close() appelé. (simulé).")
        self.connected = False

class SimulatedKafkaFuture:
    def __init__(self, topic, partition, value):
        self.topic = topic
        self.partition = partition
        self.value = value
        self._is_done = False
        self._success = False
        self._exception = None
        self._offset = -1

    def _set_result(self, success, offset=None, exception=None):
        self._is_done = True
        self._success = success
        self._offset = offset
        self._exception = exception

    def get(self, timeout=None):
        if not self._is_done: # Should be rare in this sync simulation
            time.sleep(0.001) # Simulate a tiny wait
            if not self._is_done:
                 raise SimulatedKafkaException("Kafka future timed out (simulated)")
        if self._success:
            return SimulatedRecordMetadata(self.topic, self.partition, self._offset)
        else:
            raise self._exception if self._exception else SimulatedKafkaException("Kafka send failed (simulated future)")
            
class SimulatedRecordMetadata:
    def __init__(self, topic, partition, offset):
        self.topic = topic
        self.partition = partition
        self.offset = offset

    def __repr__(self):
        return f"SimulatedRecordMetadata(topic='{self.topic}', partition={self.partition}, offset={self.offset})"

# --- Kafka Consumer Simulation ---
class SimulatedConsumerRecord:
    def __init__(self, topic, partition, offset, key, value, timestamp=None, headers=None, error=None):
        self.topic = topic
        self.partition = partition
        self.offset = offset
        self.key = key # Usually bytes
        self.value = value # Usually bytes (raw from Kafka), deserialized by consumer logic
        self.timestamp = timestamp or int(time.time() * 1000)
        self.headers = headers or []
        self.error = error # To simulate deserialization errors

    def __repr__(self):
        # For printing, decode key/value if they are bytes
        key_repr = self.key.decode('utf-8', 'ignore') if isinstance(self.key, bytes) else self.key
        value_repr = self.value.decode('utf-8', 'ignore') if isinstance(self.value, bytes) else self.value
        return (f"SimulatedConsumerRecord(topic='{self.topic}', offset={self.offset}, "
                f"key={key_repr}, value={str(value_repr)[:60] if value_repr else 'None'}..., error={self.error})")

class SimulatedKafkaConsumer:
    def __init__(self, *topics, bootstrap_servers=None, group_id=None, value_deserializer=None, auto_offset_reset='latest', **kwargs):
        self.topics = list(topics)
        self.bootstrap_servers = bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        self.group_id = group_id
        self.value_deserializer = value_deserializer or (lambda v_bytes: json.loads(v_bytes.decode('utf-8')) if v_bytes else None)
        self.auto_offset_reset = auto_offset_reset
        self.closed = False
        self.subscribed = False
        self.message_queue = [] 
        self.current_offset_sim = 0 
        print(f"SimulatedKafkaConsumer initialisé. Serveurs: {self.bootstrap_servers}, Group ID: {self.group_id}, Deserializer: {'JSON Lambda' if value_deserializer else 'Default JSON Lambda'}")
        if self.topics:
            self.subscribe(self.topics)

    def subscribe(self, topics):
        self.topics = list(topics)
        self.subscribed = True
        print(f"  SimulatedKafkaConsumer: Souscrit aux topics: {self.topics}")
        self._populate_simulated_messages(count=2) 

    def _populate_simulated_messages(self, count=1):
        if not self.subscribed or not self.topics: return
        for i in range(count):
            topic = random.choice(self.topics)
            sim_value_dict = {"message_id": f"sim_{self.current_offset_sim + i}", "data": f"Simulated data {random.randint(1,100)} for {topic}", "ts": time.time()}
            raw_bytes_value = json.dumps(sim_value_dict).encode('utf-8')
            # Simulate key as bytes as well
            sim_key_bytes = f"key_{self.current_offset_sim + i}".encode('utf-8')
            record = SimulatedConsumerRecord(
                topic=topic, partition=0, offset=self.current_offset_sim + i,
                key=sim_key_bytes, value=raw_bytes_value, 
            )
            self.message_queue.append(record)
        self.current_offset_sim += count
        if count > 0: print(f"  SimulatedKafkaConsumer: {count} messages factices ajoutés à la file pour {self.topics}.")

    def poll(self, timeout_ms=0, max_records=None): # max_records not implemented in sim
        if self.closed or not self.subscribed:
            # print("  SimulatedKafkaConsumer: Poll sur consommateur fermé ou non souscrit.")
            return None 
        
        print(f"  SimulatedKafkaConsumer: poll(timeout={timeout_ms/1000.0 if timeout_ms else 0}s) appelé...")
        if not self.message_queue:
            if timeout_ms > 0: 
                time.sleep(min(timeout_ms / 1000.0, 0.1)) # Simulate some wait, but not too long for tests
            if random.random() < 0.15: self._populate_simulated_messages(1) # Occasionally add new message
            if not self.message_queue: 
                print("  SimulatedKafkaConsumer: Aucun message dans la file après poll.")
                return None # No messages available
        
        record_with_bytes = self.message_queue.pop(0) # Get message with raw bytes value
        
        # Attempt deserialization
        deserialized_value = None
        error_obj = None
        try:
            deserialized_value = self.value_deserializer(record_with_bytes.value)
        except Exception as e:
            print(f"  SimulatedKafkaConsumer: Erreur de désérialisation: {e}")
            error_obj = e # Attach error to the record
        
        # Return a new record, but with the deserialized value (or original bytes if error)
        # The 'value' field of the returned record should be the deserialized one.
        final_record = SimulatedConsumerRecord(
            topic=record_with_bytes.topic, partition=record_with_bytes.partition, 
            offset=record_with_bytes.offset, key=record_with_bytes.key, 
            value=deserialized_value if not error_obj else record_with_bytes.value, # Use deserialized value
            timestamp=record_with_bytes.timestamp, headers=record_with_bytes.headers, 
            error=error_obj # Store the exception object itself if one occurred
        )
        print(f"  SimulatedKafkaConsumer: Message retourné: {final_record}")
        return final_record

    def commit(self, message=None, offsets=None, asynchronous=True): # asynchronous not used in sim
        if message: print(f"  SimulatedKafkaConsumer: commit(message=offset {message.offset}) (simulé).")
        elif offsets: print(f"  SimulatedKafkaConsumer: commit(offsets={offsets}) (simulé).")
        else: print(f"  SimulatedKafkaConsumer: commit() général (simulé).")
        return True # Simulate success

    def close(self):
        print("  SimulatedKafkaConsumer: close() appelé (simulé).")
        self.closed = True
        self.subscribed = False

    def __iter__(self):
        if not self.subscribed: print("AVERTISSEMENT: Itération sur un consommateur non souscrit.")
        return self
    
    def __next__(self):
        if self.closed: raise StopIteration
        # Loop to get a message, handling empty polls
        while not self.closed:
            msg = self.poll(timeout_ms=100) # Poll with a short timeout for iteration
            if msg: return msg
            # If queue is empty, occasionally add new messages to simulate a live stream
            if not self.message_queue and random.random() > 0.9 : self._populate_simulated_messages(1) 
            elif not self.message_queue: time.sleep(0.01) # Small sleep if queue is empty to prevent busy loop

if __name__ == "__main__":
    print("\n--- Test du Producteur Kafka Simulé ---")
    try:
        producer = SimulatedKafkaProducer(bootstrap_servers=['localhost:19092'])
        if producer.connected:
            for i in range(2): 
                msg_val = {'message': f'Message de test P->C {i}', 'id': f'pc_test_{i}'}
                future = producer.send('zt_agent_alerts', value=msg_val, key=f'key{i}')
                try: metadata = future.get(timeout=0.5); print(f"  Producteur: Msg {i} envoyé. Meta: {metadata}")
                except Exception as e: print(f"  Producteur: Erreur envoi msg {i}: {e}")
        producer.close()
    except Exception as e: print(f"Erreur test Producteur: {e}")
    
    print("\n--- Test du Consommateur Kafka Simulé ---")
    consumer = None
    try:
        consumer = SimulatedKafkaConsumer('zt_agent_alerts', 'another_topic', 
                                          group_id='test_zt_group', 
                                          bootstrap_servers=['localhost:19092'])
        
        print("\nTest avec poll():")
        for i in range(4): 
            msg = consumer.poll(timeout_ms=50) # Shorter timeout for faster test
            if msg: print(f"  Poll {i+1}: Reçu: {msg.value} (Erreur: {msg.error})")
            else: print(f"  Poll {i+1}: Aucun message.")
            if i < 2 and not consumer.message_queue : consumer._populate_simulated_messages(1) # Ensure some messages

        print("\nTest avec itération (for msg in consumer):")
        for i, message in enumerate(consumer):
            if i >= 2: print("  (Test) Limite d'itération atteinte."); break 
            print(f"  Iter {i+1}: Reçu: {message.value} (Erreur: {message.error})")
            if not consumer.message_queue and i < 1 : consumer._populate_simulated_messages(1) # Ensure some messages for iteration

        # Test deserialization error
        print("\nTest erreur de désérialisation:")
        consumer.message_queue.append(
            SimulatedConsumerRecord("zt_agent_alerts", 0, 999, b"key_err", b"this is not json")
        )
        err_msg = consumer.poll(timeout_ms=10)
        if err_msg:
            print(f"  Poll (err): Reçu: {err_msg.value} (Erreur: {type(err_msg.error).__name__ if err_msg.error else 'None'})")
            assert err_msg.error is not None, "Deserialization error was expected!"
        else:
            print("  Poll (err): Aucun message pour le test d'erreur (inattendu).")


    except Exception as e: print(f"Erreur test Consommateur: {type(e).__name__} - {e}")
    finally:
        if consumer: consumer.close()

    print("\nFin des tests kafka_client.py.")
