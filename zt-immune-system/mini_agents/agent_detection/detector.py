# detector.py
# - Charge les règles YARA/Sigma
# - Sandboxing via seccomp_profile.json (conceptuel)
# - Méthodes :
#   - scan_memory()
#   - analyze_network_flow(pcap)
# Envoie les alertes à l'IA via Kafka (topic alerts_raw)

import os
import json # For Kafka messages (simulation)
import time # For timestamps
import random # For simulation logic
# import yaml # Pour charger sandbox_config.yaml (si besoin dans le code)
# import yara # Placeholder pour le moteur YARA
# Placeholder pour un moteur Sigma (souvent une lib externe ou un script de conversion)

# KAFKA_BROKER = "kafka_server:9092" # Configurable
# KAFKA_ALERTS_TOPIC = "alerts_raw"   # Configurable
# RULES_PATH = "zt-immune-system/mini_agents/agent_detection/rules/" # Defined locally in methods
# SANDBOX_CONFIG_PATH = "zt-immune-system/mini_agents/agent_detection/sandbox_config.yaml" # Defined locally

print("Initialisation du logger pour Agent Detection (detector.py) (placeholder)")

class DetectionAgent:
    def __init__(self, agent_id="agent_det_001"):
        self.agent_id = agent_id
        # self.kafka_producer = KafkaProducerWrapper(KAFKA_BROKER) # Simulation
        print(f"Agent de Détection {self.agent_id} initialisé. Producteur Kafka (simulé) prêt.")

        self.yara_rules = None
        self.sigma_rules = {} # Dictionnaire pour stocker les règles Sigma parsées
        self.ensure_rules_path_exists() # Ensure rules path exists before loading
        self.load_rules()
        self.apply_sandboxing_conceptual()

    def ensure_rules_path_exists(self):
        rules_path = "zt-immune-system/mini_agents/agent_detection/rules/"
        if not os.path.exists(rules_path):
            try:
                os.makedirs(rules_path)
                print(f"Répertoire des règles créé: {rules_path}")
            except OSError as e:
                print(f"Erreur lors de la création du répertoire des règles {rules_path}: {e}")

    def load_rules(self):
        """Charge les règles YARA et Sigma depuis le répertoire des règles."""
        rules_path = "zt-immune-system/mini_agents/agent_detection/rules/"
        print(f"Chargement des règles depuis {rules_path} (placeholder).")

        # Charger les règles YARA (simulation)
        # try:
        #     yara_rule_files = [f for f in os.listdir(rules_path) if f.endswith(".yar") or f.endswith(".yara")]
        #     if yara_rule_files:
        #         # self.yara_rules = yara.compile(filepaths={namespace: os.path.join(rules_path, filename) for namespace, filename in enumerate(yara_rule_files)})
        #         self.yara_rules = "compiled_yara_rules_placeholder"
        #         print(f"Règles YARA chargées et compilées (simulé): {yara_rule_files}")
        #     else:
        #         print("Aucune règle YARA trouvée.")
        # except Exception as e:
        #     print(f"Erreur lors du chargement/compilation des règles YARA: {e}")
        #     self.yara_rules = None
        self.yara_rules = "compiled_yara_rules_placeholder" # Keep it simple for placeholder
        # Check if dummy yara file exists for more realistic placeholder message
        if os.path.exists(os.path.join(rules_path, "dummy_malware.yar")):
             print(f"Règles YARA chargées et compilées (simulé - ex: dummy_malware.yar).")
        else:
            print(f"Règles YARA chargées et compilées (simulé - aucun fichier .yar trouvé).")


        # Charger les règles Sigma (simulation)
        # try:
        #     sigma_rule_files = [f for f in os.listdir(rules_path) if f.endswith(".yml") or f.endswith(".yaml")]
        #     for sigma_file in sigma_rule_files:
        #         with open(os.path.join(rules_path, sigma_file), 'r') as f_sigma:
        #             # rule_content = yaml.safe_load(f_sigma)
        #             rule_content = {"title": f"Simulated Sigma Rule from {sigma_file}", "detection": {"keywords": ["bad_stuff"]}}
        #             self.sigma_rules[rule_content.get('title', sigma_file)] = rule_content
        #             print(f"Règle Sigma chargée (simulé): {rule_content.get('title', sigma_file)}")
        #     if not self.sigma_rules:
        #         print("Aucune règle Sigma trouvée.")
        # except Exception as e:
        #     print(f"Erreur lors du chargement des règles Sigma: {e}")
        # Simplified placeholder loading
        dummy_sigma_path = os.path.join(rules_path, "dummy_network.yml")
        if os.path.exists(dummy_sigma_path):
            self.sigma_rules["Dummy Network Rule"] = {"title": "Dummy Network Rule", "detection": {"keywords": ["evil.com", "suspicious_ua"]}}
            print(f"Règles Sigma chargées (simulé - ex: dummy_network.yml).")
        else:
            self.sigma_rules["Simulated Network Anomaly Rule"] = {"title": "Simulated Network Anomaly", "detection": {"keywords": ["suspicious_domain.com", "CnC_pattern"]}}
            print(f"Règles Sigma chargées (simulé - aucun fichier .yml trouvé, utilisation de la règle par défaut).")


    def apply_sandboxing_conceptual(self):
        """
        Applique conceptuellement les restrictions de sandboxing.
        """
        sandbox_config_path = "zt-immune-system/mini_agents/agent_detection/sandbox_config.yaml"
        print(f"Lecture de la configuration de sandboxing depuis {sandbox_config_path} (conceptuel).")
        # try:
        #     with open(sandbox_config_path, 'r') as f_sandbox:
        #         config = yaml.safe_load(f_sandbox) # Requires PyYAML
        #         print(f"Configuration de sandbox chargée: CPU {config.get('CPU', 'N/A')}, RAM {config.get('RAM', 'N/A')}")
        #         print(f"Syscalls à bloquer (conceptuel): {config.get('Syscalls_bloques', [])}")
        # except FileNotFoundError:
        #     print(f"Fichier de configuration sandbox non trouvé: {sandbox_config_path}. Utilisation des paramètres par défaut.")
        # except Exception as e:
        #     print(f"Erreur lors du chargement de la config de sandbox: {e}")
        print("Restrictions de sandboxing (CPU, RAM, Syscalls) appliquées conceptuellement.")


    def send_alert(self, alert_data):
        """Envoie une alerte à l'IA Principale via Kafka."""
        payload = {
            "agent_id": self.agent_id,
            "timestamp": time.time(),
            "alert_type": "detection_event",
            "data": alert_data
        }
        # self.kafka_producer.send_message(KAFKA_ALERTS_TOPIC, payload)
        # Using json.dumps for better readability of complex alert_data in logs
        print(f"ALERTE ENVOYÉE (simulé via Kafka topic 'alerts_raw'): {json.dumps(payload, indent=2)}")


    def scan_memory(self, process_id=None):
        """
        Scan la mémoire d'un processus spécifique ou la mémoire système pour des patterns YARA.
        """
        target = f"processus {process_id}" if process_id else "mémoire système"
        print(f"Scan mémoire sur {target} en utilisant les règles YARA (simulé).")

        if not self.yara_rules: # self.yara_rules is a string placeholder
            print("Règles YARA (placeholder) non initialisées correctement, impossible de scanner la mémoire.")
            return []

        simulated_matches = []
        if random.random() < 0.1:
            match_data = {
                "rule_name": "SimulatedMalwarePattern_Generic",
                "process_id": process_id,
                "details": "Pattern de malware générique trouvé en mémoire (simulé)."
            }
            simulated_matches.append(match_data)
            print(f"Correspondance YARA trouvée (simulé): {match_data['rule_name']}")
            self.send_alert(match_data)
        else:
            print("Aucune correspondance YARA trouvée en mémoire (simulé).")

        return simulated_matches


    def analyze_network_flow(self, pcap_data_or_path, flow_metadata=None):
        """
        Analyse un flux réseau (données PCAP ou chemin vers fichier) avec des règles Sigma.
        """
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
                    # Convert flow_metadata to string for simple keyword search
                    if keyword.lower() in str(flow_metadata).lower():
                        alert = {
                            "rule_title": rule_title,
                            "sigma_match": True,
                            "flow_metadata": flow_metadata,
                            "triggering_keyword": keyword,
                            "details": f"Flux réseau correspondant à la règle Sigma '{rule_title}' (mot-clé: {keyword}) (simulé)."
                        }
                        simulated_alerts.append(alert)
                        print(f"Correspondance Sigma trouvée (simulé): {rule_title}")
                        self.send_alert(alert)
                        break

        if not simulated_alerts:
            print("Aucune correspondance Sigma trouvée dans le flux réseau (simulé).")

        return simulated_alerts

if __name__ == "__main__":
    print("\n--- Démarrage de l'Agent de Détection en mode direct ---")

    rules_dir = "zt-immune-system/mini_agents/agent_detection/rules/"
    # Ensure rules_dir exists for dummy file creation
    if not os.path.exists(rules_dir):
        try:
            os.makedirs(rules_dir)
            print(f"Répertoire des règles de test créé: {rules_dir}")
        except OSError as e:
            print(f"Erreur IO lors de la création de {rules_dir}: {e}")

    try:
        with open(os.path.join(rules_dir, "dummy_malware.yar"), "w") as f:
            f.write("rule dummy_malware { meta: author=\"test\"; strings: $hex = { E2 34 A1 }; condition: $hex }")
    except IOError as e:
        print(f"Erreur IO lors de la création de dummy_malware.yar: {e}")

    try:
        with open(os.path.join(rules_dir, "dummy_network.yml"), "w") as f:
            f.write("title: Dummy Network Rule\ndetection:\n  keywords: ['evil.com', 'suspicious_ua']")
    except IOError as e:
        print(f"Erreur IO lors de la création de dummy_network.yml: {e}")


    agent = DetectionAgent(agent_id="test_detector_01")

    print("\n--- Test Scan Mémoire ---")
    agent.scan_memory(process_id=1234)
    agent.scan_memory()

    print("\n--- Test Analyse Flux Réseau ---")
    sample_flow_suspicious = {
        "src_ip": "192.168.1.100", "dst_ip": "1.2.3.4", "dst_port": 80,
        "http_host": "evil.com", "user_agent": "SuspiciousUA/1.0" # Changed to match dummy rule
    }
    agent.analyze_network_flow("path/to/capture.pcap", flow_metadata=sample_flow_suspicious)

    sample_flow_normal = {
        "src_ip": "192.168.1.101", "dst_ip": "8.8.8.8", "dst_port": 53,
        "dns_query": "google.com"
    }
    agent.analyze_network_flow("path/to/another.pcap", flow_metadata=sample_flow_normal)

    # Consider commenting out cleanup for inspection on failure
    # try:
    #     if os.path.exists(os.path.join(rules_dir, "dummy_malware.yar")):
    #         os.remove(os.path.join(rules_dir, "dummy_malware.yar"))
    #     if os.path.exists(os.path.join(rules_dir, "dummy_network.yml")):
    #         os.remove(os.path.join(rules_dir, "dummy_network.yml"))
    # except IOError as e:
    #     print(f"Erreur IO lors du nettoyage des fichiers de règles de test: {e}")


    print("\n--- Fin du test direct de l'Agent de Détection ---")
