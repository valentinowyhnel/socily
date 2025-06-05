# detector.py
# - Charge les règles YARA/Sigma
# - Sandboxing via seccomp_profile.json (conceptuel)
# - Méthodes :
#   - scan_memory()
#   - analyze_network_flow(pcap)
# Envoie les alertes à l'IA via Kafka (topic alerts_raw)

import os
import json 
import time 
import random # For simulation
# import yaml # Pour charger sandbox_config.yaml (si besoin dans le code)
# import yara # Placeholder pour le moteur YARA

# --- Import Kafka Producer ---
import sys
# Calculate the path to the 'ia_principale' directory from 'mini_agents/agent_detection'
# Current file: zt-immune-system/mini_agents/agent_detection/detector.py
# Target: zt-immune-system/ia_principale/communication/kafka_client.py
# Path from current file: ../../ia_principale/communication
path_to_ia_principale_communication = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', '..', 'ia_principale', 'communication'))
sys.path.append(path_to_ia_principale_communication)

try:
    from kafka_client import SimulatedKafkaProducer, SimulatedKafkaException
except ImportError as e:
    print(f"ERREUR CRITIQUE: Impossible d'importer SimulatedKafkaProducer depuis kafka_client.py: {e}")
    print(f"Chemin de recherche Python actuel: {sys.path}")
    print(f"Chemin calculé pour kafka_client: {os.path.abspath(path_to_ia_principale_communication)}")
    # Fallback to a dummy class if import fails, so the rest of the file can be tested structurally
    class SimulatedKafkaProducer:
        def __init__(self, *args, **kwargs): print("Dummy SimulatedKafkaProducer (import a échoué)")
        def send(self, *args, **kwargs): print("Dummy send (import a échoué)"); return type('DummyFuture', (), {'get': lambda s,t=None: None})() # Added t=None for timeout
        def flush(self, *args, **kwargs): pass
        def close(self, *args, **kwargs): pass
    class SimulatedKafkaException(Exception): pass


# --- Configuration ---
KAFKA_BOOTSTRAP_SERVERS_CONFIG = ['kafka_sim_server:9092'] # Agent-specific config or from a shared config
KAFKA_ALERTS_TOPIC = "zt_agent_alerts" # Standardized topic name
RULES_PATH = os.path.join(os.path.dirname(__file__), "rules") 
SANDBOX_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "sandbox_config.yaml")

print("Initialisation du logger pour Agent Detection (detector.py) (placeholder)") # Simulates logging

class DetectionAgent:
    def __init__(self, agent_id="agent_det_001"):
        self.agent_id = agent_id
        self.kafka_producer = None
        try:
            self.kafka_producer = SimulatedKafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS_CONFIG
                # Add other relevant Kafka producer settings here, e.g., retries, acks
            )
            print(f"Agent de Détection {self.agent_id} initialisé. Producteur Kafka (simulé) prêt.")
        except SimulatedKafkaException as e: # Catch custom Kafka exception
            print(f"ERREUR Kafka: Échec de l'initialisation du producteur pour {self.agent_id}: {e}")
            print("  L'agent fonctionnera en mode dégradé (les alertes ne seront pas envoyées).")
        except Exception as e: # Catch any other unexpected errors during init
            print(f"ERREUR INATTENDUE lors de l'initialisation du producteur Kafka: {type(e).__name__} - {e}")
            print("  L'agent fonctionnera en mode dégradé.")


        self.yara_rules = None # Placeholder for compiled YARA rules
        self.sigma_rules = {}  # Placeholder for parsed Sigma rules
        # self.ensure_rules_path_exists() # Already done in original version if __main__ created files
        self.load_rules()
        self.apply_sandboxing_conceptual()

    def load_rules(self):
        print(f"Chargement des règles depuis {RULES_PATH} (placeholder).")
        # Actual YARA/Sigma loading logic would go here
        self.yara_rules = "compiled_yara_rules_placeholder"
        if os.path.exists(os.path.join(RULES_PATH, "malware_signature.yar")): # Check if specific file exists
             print(f"  Règles YARA chargées et compilées (simulé - ex: malware_signature.yar).")
        else:
            print(f"  Règles YARA chargées et compilées (simulé - aucun fichier .yar trouvé).")

        sigma_rule_file = os.path.join(RULES_PATH, "network_anomaly.yml")
        if os.path.exists(sigma_rule_file):
            self.sigma_rules["Network Anomaly Rule (from file)"] = {"title": "Network Anomaly from file", "detection": {"keywords": ["evil.com", "suspicious_ip"]}}
            print(f"  Règles Sigma chargées (simulé - ex: {os.path.basename(sigma_rule_file)}).")
        else:
            self.sigma_rules["Simulated Network Anomaly Rule (default)"] = {"title": "Simulated Network Anomaly (default)", "detection": {"keywords": ["suspicious_domain.com", "CnC_pattern"]}}
            print(f"  Règles Sigma chargées (simulé - aucun fichier .yml trouvé, utilisation de la règle par défaut).")


    def apply_sandboxing_conceptual(self):
        print(f"Lecture de la configuration de sandboxing depuis {SANDBOX_CONFIG_PATH} (conceptuel).")
        # Actual sandboxing application logic (OS-dependent) would be here
        print("Restrictions de sandboxing (CPU, RAM, Syscalls) appliquées conceptuellement.")

    def send_alert(self, alert_data):
        """Envoie une alerte à l'IA Principale via Kafka en utilisant le producteur."""
        if not self.kafka_producer or not self.kafka_producer.connected: # Check if producer exists and is connected
            print(f"ALERTE NON ENVOYÉE (producteur Kafka non disponible ou non connecté): {alert_data.get('rule_name', alert_data.get('rule_title', 'N/A'))}")
            return

        payload = {
            "agent_id": self.agent_id,
            "timestamp": time.time(),
            "alert_type": "detection_event", 
            "data": alert_data 
        }
        
        try:
            alert_identifier = alert_data.get('rule_name', alert_data.get('rule_title', 'Info sans titre'))
            print(f"Tentative d'envoi d'alerte au topic '{KAFKA_ALERTS_TOPIC}': {alert_identifier}")
            future = self.kafka_producer.send(KAFKA_ALERTS_TOPIC, value=payload, key=self.agent_id)
            metadata = future.get(timeout=10) 
            print(f"  Alerte '{alert_identifier}' envoyée avec succès. Métadonnées: {metadata}")
        except SimulatedKafkaException as e:
            print(f"  ERREUR Kafka lors de l'envoi de l'alerte '{alert_identifier}': {e}")
        except Exception as e: 
            print(f"  ERREUR INATTENDUE lors de l'envoi de l'alerte Kafka '{alert_identifier}': {type(e).__name__} - {e}")


    def scan_memory(self, process_id=None):
        target = f"processus {process_id}" if process_id else "mémoire système"
        print(f"Scan mémoire sur {target} en utilisant les règles YARA (simulé).")
        if not self.yara_rules:
            print("Aucune règle YARA chargée, impossible de scanner la mémoire.")
            return []
        simulated_matches = []
        if random.random() < 0.1: 
            match_info = {
                "rule_name": "SimulatedMalwarePattern_GenericMemory",
                "scan_target": target,
                "process_id": process_id,
                "details": "Pattern de malware générique trouvé en mémoire (simulé)."
            }
            simulated_matches.append(match_info)
            print(f"  Correspondance YARA trouvée (simulé): {match_info['rule_name']}")
            self.send_alert(match_info) 
        else:
            print("  Aucune correspondance YARA trouvée en mémoire (simulé).")
        return simulated_matches

    def analyze_network_flow(self, pcap_data_or_path, flow_metadata=None):
        source_info = f"fichier PCAP {pcap_data_or_path}" if isinstance(pcap_data_or_path, str) else "données PCAP en mémoire"
        print(f"Analyse du flux réseau depuis {source_info} avec les règles Sigma (simulé).")
        if not self.sigma_rules:
            print("Aucune règle Sigma chargée, impossible d'analyser le flux réseau.")
            return []
        simulated_alerts = []
        if flow_metadata:
            for rule_title, rule_content in self.sigma_rules.items():
                detection_keywords = rule_content.get("detection", {}).get("keywords", [])
                for keyword in detection_keywords:
                    if keyword.lower() in str(flow_metadata).lower():
                        alert_info = {
                            "rule_title": rule_title,
                            "sigma_match": True,
                            "flow_metadata": flow_metadata,
                            "triggering_keyword": keyword,
                            "details": f"Flux réseau correspondant à la règle Sigma '{rule_title}' (mot-clé: {keyword}) (simulé)."
                        }
                        simulated_alerts.append(alert_info)
                        print(f"  Correspondance Sigma trouvée (simulé): {rule_title}")
                        self.send_alert(alert_info) 
                        break 
        if not simulated_alerts:
            print("  Aucune correspondance Sigma trouvée dans le flux réseau (simulé).")
        return simulated_alerts

    def shutdown(self):
        """Cleanly shuts down the agent, including the Kafka producer."""
        print(f"Arrêt de l'Agent de Détection {self.agent_id}...")
        if self.kafka_producer:
            try:
                self.kafka_producer.flush(timeout=5) 
                self.kafka_producer.close(timeout=5)
                print("  Producteur Kafka fermé proprement.")
            except SimulatedKafkaException as e:
                print(f"  Erreur lors de la fermeture du producteur Kafka: {e}")
            except Exception as e:
                print(f"  Erreur inattendue lors de la fermeture du producteur Kafka: {type(e).__name__} - {e}")


if __name__ == "__main__":
    print("\nDémarrage de l'Agent de Détection en mode direct (avec Kafka Producer intégré).")
    
    # Ensure rules directory exists for dummy file creation for load_rules simulation
    rules_dir_main = os.path.join(os.path.dirname(__file__), "rules")
    if not os.path.exists(rules_dir_main): 
        try:
            os.makedirs(rules_dir_main)
            print(f"  Répertoire des règles de test créé: {rules_dir_main}")
        except OSError as e:
             print(f"  Erreur IO lors de la création de {rules_dir_main}: {e}")
    
    # Create dummy rule files if they don't exist, so load_rules simulation is more consistent
    if not os.path.exists(os.path.join(rules_dir_main, "malware_signature.yar")):
        with open(os.path.join(rules_dir_main, "malware_signature.yar"), "w") as f: f.write("# Dummy YARA rule for testing")
    if not os.path.exists(os.path.join(rules_dir_main, "network_anomaly.yml")):
        with open(os.path.join(rules_dir_main, "network_anomaly.yml"), "w") as f: f.write("# Dummy Sigma rule for testing")


    print("\n--- Test Agent avec potentiel échec d'init Kafka ---")
    original_random_func = random.random # Save original random
    def temporary_high_fail_random(): return 0.99 # Increase chance of Kafka connection failure for this test
    random.random = temporary_high_fail_random
    
    agent_test_init_fail = DetectionAgent(agent_id="test_detector_init_fail_002")
    agent_test_init_fail.scan_memory(111) 
    agent_test_init_fail.shutdown()
    random.random = original_random_func # Restore


    print("\n--- Test Agent normal ---")
    agent = DetectionAgent(agent_id="test_detector_main_001")

    print("\n--- Test Scan Mémoire (avec envoi Kafka) ---")
    random.random = lambda: 0.05 # Force YARA detection
    agent.scan_memory(process_id=1234)
    random.random = original_random_func 

    agent.scan_memory() 

    print("\n--- Test Analyse Flux Réseau (avec envoi Kafka) ---")
    sample_flow_suspicious = {
        "src_ip": "192.168.1.100", "dst_ip": "1.2.3.4", "dst_port": 80, 
        "http_host": "suspicious_domain.com", "user_agent": "BadBrowser/1.0" # Matches default Sigma rule
    }
    agent.analyze_network_flow("path/to/capture.pcap", flow_metadata=sample_flow_suspicious)
    
    sample_flow_normal = {
        "src_ip": "192.168.1.101", "dst_ip": "8.8.8.8", "dst_port": 53,
        "dns_query": "google.com"
    }
    agent.analyze_network_flow("path/to/another.pcap", flow_metadata=sample_flow_normal)
    
    agent.shutdown() 

    print("\nFin du test direct de l'Agent de Détection (avec Kafka).")
