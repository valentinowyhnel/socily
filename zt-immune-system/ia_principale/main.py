# main.py
"""
Main entry point for the ZT Immune System's IA Principale (Main AI) module.

This module initializes and runs a FastAPI application that serves as the primary interface
and orchestration hub. It manages several key background tasks:
- An Orchestrator instance for processing security alerts and deciding on actions.
- A KafkaProducer for sending commands (e.g., from WebSocket interactions) to Kafka.
- A KafkaConsumer for ingesting raw security alerts from Kafka to be processed by the Orchestrator.
- A WebSocket ConnectionManager for handling real-time communication with dashboard clients.
- A KafkaConsumer for ingesting frontend-specific alerts from Kafka and broadcasting
  them to connected WebSocket clients.

The application lifecycle (startup and shutdown of these components) is managed
by FastAPI's lifespan events.
"""

import asyncio
import threading
import os
import logging

from fastapi import FastAPI

from . import orchestrator
from .data_ingestion import start_alerts_raw_consumer
# websocket_server_router will be imported AFTER app.state.connection_manager is set in startup.
# from .communication.websocket_server import websocket_server_router
from .communication.kafka_client import KafkaProducerWrapper
# ConnectionManager will be imported in startup_event.
# from .communication.websocket_server import ConnectionManager


# Configure logger for this module
logger = logging.getLogger(__name__)
# Ensure basicConfig is called only if no handlers are configured for the root logger
# or this specific logger. This helps prevent overriding Uvicorn's logging if it's already set up.
if not logging.getLogger().hasHandlers() and not logger.hasHandlers():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
    )

# Global variables for background task management for raw alerts consumer
orch_instance: orchestrator.Orchestrator | None = None # Instance of the alert orchestrator
raw_alerts_consumer_thread: threading.Thread | None = None # Thread for consuming raw alerts
raw_alerts_stop_event: threading.Event | None = None # Event to signal raw alerts consumer to stop
# Other components like KafkaProducerWrapper, ConnectionManager, and frontend alerts consumer
# will be stored in app.state to be accessible across the application.

# --- FastAPI Application Setup ---
app = FastAPI(
    title="ZT Immune System - IA Principale",
    description="Module principal de l'IA pour la surveillance et l'orchestration des alertes.",
    version="0.1.0",
    # Lifespan context manager can also be used instead of @app.on_event,
    # but @app.on_event is used here for clarity of individual startup/shutdown tasks.
)

# --- Lifespan Events (Startup and Shutdown) ---
@app.on_event("startup")
async def startup_event():
    """
    Handles application startup logic:
    - Initializes the Orchestrator.
    - Initializes the Kafka Producer for WebSocket command submissions.
    - Initializes the WebSocket ConnectionManager for managing client connections.
    - Starts a Kafka consumer thread for ingesting raw security alerts.
    - Starts a Kafka consumer thread for ingesting alerts destined for frontend broadcast.
    """
    global orch_instance, raw_alerts_consumer_thread, raw_alerts_stop_event
    logger.info("Application startup sequence initiated...")

    # Kafka Configuration - Central place for Kafka broker address
    kafka_broker = os.environ.get("KAFKA_BROKER_ADDRESS", "localhost:9092")
    logger.info(f"Using Kafka Broker Address: {kafka_broker}")

    # Config for raw alerts consumer (processed by orchestrator)
    raw_alerts_topic_name = os.environ.get("KAFKA_ALERTS_RAW_TOPIC", "alerts_raw")
    raw_alerts_group_id_name = os.environ.get("KAFKA_ALERTS_RAW_GROUP_ID", "orchestrator_alerts_group_1")

    # Config for frontend alerts consumer (broadcast via WebSockets)
    # These are stored on app.state to be accessible by the consumer function if needed,
    # though passed directly in this setup.
    app.state.frontend_alerts_topic = os.environ.get("KAFKA_FRONTEND_ALERTS_TOPIC", "frontend_alerts")
    app.state.frontend_alerts_group_id = os.environ.get("KAFKA_FRONTEND_ALERTS_GROUP_ID", "frontend_alerts_websocket_group")

    # Initialize Orchestrator
    try:
        orch_instance = orchestrator.Orchestrator()
        logger.info("Core Orchestrator initialized successfully.")
    except Exception as e:
        logger.exception("Failed to initialize Orchestrator.")
        # Depending on severity, might want to raise an error to stop app startup
        # For now, log and continue, other components might still work.

    # Initialize KafkaProducerWrapper for WebSocket command submissions, stored in app.state
    try:
        app.state.kafka_producer = KafkaProducerWrapper(bootstrap_servers=kafka_broker)
        if app.state.kafka_producer.producer:
            logger.info(f"KafkaProducer for WebSocket commands initialized (Broker: {kafka_broker}).")
        else:
            logger.error(f"KafkaProducer for WebSocket commands failed to connect (Broker: {kafka_broker}). WebSocket command sending will be impacted.")
    except Exception as e:
        logger.exception(f"Failed to initialize KafkaProducer for WebSocket commands (Broker: {kafka_broker}).")
        app.state.kafka_producer = None # Ensure it's None if init fails

    # Initialize WebSocket ConnectionManager and store in app.state
    try:
        from .communication.websocket_server import ConnectionManager # Deferred import
        app.state.connection_manager = ConnectionManager()
        logger.info("WebSocket ConnectionManager initialized successfully.")
    except Exception as e:
        logger.exception("Failed to initialize WebSocket ConnectionManager.")
        app.state.connection_manager = None # Ensure it's None


    # --- Kafka Consumer for Raw Alerts (feeding the Orchestrator) ---
    if orch_instance: # Only start if orchestrator is available
        logger.info(f"Initializing Kafka consumer for raw alerts: Topic='{raw_alerts_topic_name}', GroupID='{raw_alerts_group_id_name}'")
        raw_alerts_stop_event = threading.Event()
        raw_alerts_consumer_thread = threading.Thread(
            target=start_alerts_raw_consumer,
            args=(
                orch_instance,
                kafka_broker,
                raw_alerts_topic_name,
                raw_alerts_group_id_name,
                raw_alerts_stop_event
            ),
            name="KafkaRawAlertsConsumerThread",
            daemon=True
        )
        try:
            raw_alerts_consumer_thread.start()
            logger.info("Kafka raw_alerts consumer thread started.")
        except Exception as e:
            logger.exception("Failed to start Kafka raw_alerts consumer thread.")
    else:
        logger.warning("Orchestrator not available, Kafka raw_alerts consumer thread will not start.")

    # --- Kafka Consumer for Frontend Alerts (broadcasting to WebSockets) ---
    if app.state.connection_manager: # Only start if ConnectionManager is available
        from .communication.websocket_server import start_frontend_alerts_kafka_consumer # Deferred import

        logger.info(f"Initializing Kafka consumer for frontend alerts: Topic='{app.state.frontend_alerts_topic}', GroupID='{app.state.frontend_alerts_group_id}'")
        app.state.frontend_alerts_stop_event = threading.Event()
        app.state.frontend_alerts_consumer_thread = threading.Thread(
            target=start_frontend_alerts_kafka_consumer,
            args=(
                kafka_broker,
                app.state.frontend_alerts_topic,
                app.state.frontend_alerts_group_id,
                app.state.connection_manager, # Pass the manager instance from app.state
                app.state.frontend_alerts_stop_event
            ),
            name="KafkaFrontendAlertsConsumerThread",
            daemon=True
        )
        try:
            app.state.frontend_alerts_consumer_thread.start()
            logger.info("Kafka frontend_alerts consumer thread started.")
        except Exception as e:
            logger.exception("Failed to start Kafka frontend_alerts consumer thread.")
    else:
        logger.warning("ConnectionManager not available, Kafka frontend_alerts consumer thread will not start.")

    # Now that app.state.connection_manager is initialized (or attempted),
    # we can import and include the router.
    # The router itself should be robust to connection_manager being None if it failed init.
    try:
        from .communication.websocket_server import websocket_server_router
        app.include_router(websocket_server_router, prefix="/ws_comm", tags=["WebSocket Communication"])
        logger.info("WebSocket router included.")
    except Exception as e:
        logger.exception("Failed to include WebSocket router.")

    logger.info("Application startup sequence completed.")


@app.on_event("shutdown")
async def shutdown_event():
    """
    Handles application shutdown logic for all components.

    This function is responsible for gracefully stopping all background threads
    and closing any open resources like Kafka clients.
    """
    global orch_instance, raw_alerts_consumer_thread, raw_alerts_stop_event
    logger.info("Application shutdown sequence initiated...")

    # Stop Raw Alerts Kafka Consumer
    if raw_alerts_stop_event:
        logger.info("Signalling raw alerts Kafka consumer thread to stop...")
        raw_alerts_stop_event.set()
    if raw_alerts_consumer_thread and raw_alerts_consumer_thread.is_alive():
        logger.info("Waiting for raw alerts Kafka consumer thread to join (timeout 10s)...")
        raw_alerts_consumer_thread.join(timeout=10)
        if raw_alerts_consumer_thread.is_alive():
            logger.warning("Raw alerts Kafka consumer thread did not join in specified timeout.")
        else:
            logger.info("Raw alerts Kafka consumer thread joined successfully.")
    else:
        logger.info("Raw alerts Kafka consumer thread was not active at shutdown.")

    # Stop Frontend Alerts Kafka Consumer
    frontend_alerts_stop_event_instance = getattr(app.state, 'frontend_alerts_stop_event', None)
    if frontend_alerts_stop_event_instance:
        logger.info("Signalling frontend alerts Kafka consumer thread to stop...")
        frontend_alerts_stop_event_instance.set()

    frontend_consumer_thread_instance = getattr(app.state, 'frontend_alerts_consumer_thread', None)
    if frontend_consumer_thread_instance and frontend_consumer_thread_instance.is_alive():
        logger.info("Waiting for frontend alerts Kafka consumer thread to join (timeout 10s)...")
        frontend_consumer_thread_instance.join(timeout=10)
        if frontend_consumer_thread_instance.is_alive():
            logger.warning("Frontend alerts Kafka consumer thread did not join in specified timeout.")
        else:
            logger.info("Frontend alerts Kafka consumer thread joined successfully.")
    else:
        logger.info("Frontend alerts Kafka consumer thread was not active at shutdown.")


    # Close Orchestrator (which also closes its internal Kafka producer)
    if orch_instance:
        logger.info("Closing Orchestrator...")
        try:
            orch_instance.close()
            logger.info("Orchestrator closed successfully.")
        except Exception as e:
            logger.exception("Error closing Orchestrator.")
    else:
        logger.info("Orchestrator was not initialized, no close action needed.")

    # Close global KafkaProducerWrapper used by WebSockets for commands
    kafka_producer_instance = getattr(app.state, 'kafka_producer', None)
    if kafka_producer_instance:
        logger.info("Closing KafkaProducer for WebSocket commands...")
        try:
            kafka_producer_instance.close()
            logger.info("KafkaProducer for WebSocket commands closed successfully.")
        except Exception as e:
            logger.exception("Error closing KafkaProducer for WebSocket commands.")
    else:
        logger.info("KafkaProducer for WebSocket commands was not initialized, no close action needed.")

    # ConnectionManager does not have an explicit close method in this design.
    # If it did (e.g., to clean up external resources), it would be called here.
    logger.info("Application cleanup finished.")


# --- API Endpoints ---

@app.get("/")
async def root():
    """
    Provides a basic status message indicating the API is running.
    """
    logger.info("Root endpoint '/' accessed.")
    return {"message": "IA Principale API is running. Welcome to the ZT Immune System."}

# The WebSocket router is now included at the end of the startup_event,
# once app.state.connection_manager is available and other necessary components are set up.
# This ensures that the router and its dependencies are ready when requests come in.


# --- Main execution (for running with Uvicorn) ---
# To run the application:
# uvicorn zt-immune-system.ia_principale.main:app --reload --port 8000
# Ensure KAFKA_BROKER_ADDRESS and other relevant environment variables are set.
