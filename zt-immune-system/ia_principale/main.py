# main.py
# Point d'entrée initialise tous les modules
# Boucle principale de surveillance

# Importations nécessaires (seront complétées au fur et à mesure)
from . import orchestrator
from .data_ingestion import start_alerts_raw_consumer
# from . import utils # Pour les logs et la configuration
import time
import threading
import os # For environment variable access

# Initialisation des logs (via utils.py)
# logger = utils.setup_logger('main_logger', 'main.log')
print("Initialisation du logger (placeholder)") # Placeholder

# Kafka Configuration Constants (can be moved to a config file later)
# These are defined globally here or loaded in if __name__ == "__main__":
# KAFKA_BROKER = "localhost:9092"
# ALERTS_RAW_TOPIC = "alerts_raw"
# ALERTS_CONSUMER_GROUP_ID = "orchestrator_alerts_group_1"

# Global variables for Orchestrator, Thread, and StopEvent
# orch = None # Will be initialized in __main__
consumer_thread = None
stop_event = None

def initialize_all(orchestrator_instance, kafka_broker, alerts_topic, consumer_group_id):
    """Initialise les modules nécessaires, y compris le consommateur Kafka."""
    global consumer_thread, stop_event # Allow modification of global variables

    print("Main: Initializing Kafka alert consumer thread...")
    stop_event = threading.Event()
    consumer_thread = threading.Thread(
        target=start_alerts_raw_consumer,
        args=(
            orchestrator_instance,
            kafka_broker,
            alerts_topic,
            consumer_group_id,
            stop_event
        ),
        daemon=True  # Daemon threads exit when the main program exits
    )
    consumer_thread.start()
    print("Main: Kafka alert consumer thread started.")
    # logger.info("Modules initialisés avec succès.")
    print("Modules initialisés avec succès (including consumer thread).")


def main_surveillance_loop():
    """Boucle principale de surveillance. Pour l'instant, elle ne fait que dormir."""
    # logger.info("Démarrage de la boucle principale de surveillance.")
    print("Démarrage de la boucle principale de surveillance (main_surveillance_loop).")
    # In a real scenario, this loop might do other things, or simply keep the main thread alive
    # while daemon threads do work. For now, it just keeps the program running.
    # The actual event processing from Kafka happens in the consumer_thread.
    try:
        while not (stop_event and stop_event.is_set()): # Keep main thread alive until stop_event is set
            # logger.debug("Cycle de surveillance principal...")
            # print("Cycle de surveillance principal...") # Can be noisy
            # This loop no longer directly fetches or processes events from a list.
            # That logic is now handled by the Kafka consumer thread.
            # This main loop can be used for other periodic tasks if needed, or just to keep alive.
            time.sleep(1) # Check stop_event periodically
    except KeyboardInterrupt:
        # logger.info("Arrêt de la boucle de surveillance demandé par l'utilisateur (main_surveillance_loop).")
        print("Arrêt de la boucle de surveillance demandé par l'utilisateur (main_surveillance_loop).")
    # finally:
        # Cleanup is now handled in the main __name__ == "__main__" block's finally clause.
        # print("Nettoyage de main_surveillance_loop...")


if __name__ == "__main__":
    # logger.info("Démarrage de l'IA Principale.")
    print("Démarrage de l'IA Principale.")

    # Define Kafka constants here or load from a config
    KAFKA_BROKER = os.environ.get("KAFKA_BROKER_ADDRESS", "localhost:9092")
    ALERTS_RAW_TOPIC = "alerts_raw" # This topic name is specific to alerts
    ALERTS_CONSUMER_GROUP_ID = "orchestrator_alerts_group_1"

    orch = orchestrator.Orchestrator() # Initialize orchestrator first
    # logger.info("Orchestrateur initialisé.")
    print("Main: Orchestrateur initialisé.")

    initialize_all(orch, KAFKA_BROKER, ALERTS_RAW_TOPIC, ALERTS_CONSUMER_GROUP_ID) # Initialize consumer thread

    try:
        main_surveillance_loop() # Start the main loop
    except Exception as e: # Catch any other unexpected errors from main_surveillance_loop
        print(f"Main: Exception in main_surveillance_loop: {e}")
    finally:
        # logger.info("Nettoyage avant la fermeture (main)...")
        print("Nettoyage avant la fermeture (main)...")

        if stop_event:
            print("Main: Signalling consumer thread to stop...")
            stop_event.set()

        if consumer_thread and consumer_thread.is_alive():
            print("Main: Waiting for consumer thread to join...")
            consumer_thread.join(timeout=10) # Wait for up to 10 seconds
            if consumer_thread.is_alive():
                print("Main: Consumer thread did not join in time.")
        else:
            print("Main: Consumer thread was not alive or not initialized.")

        if orch: # orch is defined in this scope
            print("Main: Closing orchestrator...")
            orch.close()
        else:
            print("Main: Orchestrator was not initialized.")

    # logger.info("IA Principale terminée.")
    print("IA Principale terminée.")
