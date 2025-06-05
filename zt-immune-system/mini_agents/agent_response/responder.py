# responder.py
# - Actions immédiates :
#   - quarantine_ip(ip)
#   - kill_process(pid)
#   - rollback_snapshot(vm_id)
# Reçoit les ordres de l'orchestrateur via WebSocket (conceptuel)
# Appelle firewall_rules.py

import time
import json # For simulated WebSocket messages
# from . import firewall_rules # Dynamically manage firewall rules
# import websocket # Placeholder for actual WebSocket client library like 'websocket-client'
import importlib.util # For dynamic loading of firewall_rules
import os # For path manipulation in dynamic loading

# ORCHESTRATOR_WS_URL = "ws://ia_principale_websocket_server/ws/response_agent" # Configurable
# AGENT_ID = "agent_resp_001"

print("Initialisation du logger pour Agent Réponse (responder.py) (placeholder)")

class ResponseAgent:
    def __init__(self, agent_id="agent_resp_001"):
        self.agent_id = agent_id
        # self.ws_client = None # WebSocket client instance
        # self.connect_to_orchestrator()
        print(f"Agent de Réponse {self.agent_id} initialisé.")
        print("Connexion WebSocket à l'orchestrateur (simulée).")

    def connect_to_orchestrator(self):
        """
        Établit une connexion WebSocket avec l'orchestrateur pour recevoir des commandes.
        (Placeholder - la gestion réelle des WebSockets est plus complexe)
        """
        # try:
        #     self.ws_client = websocket.create_connection(ORCHESTRATOR_WS_URL)
        #     print(f"Connecté à l'orchestrateur via WebSocket: {ORCHESTRATOR_WS_URL}")
        #     self.ws_client.send(json.dumps({"type": "register", "agent_id": self.agent_id, "capabilities": ["quarantine_ip", "kill_process", "rollback_snapshot"]}))
        # except Exception as e:
        #     print(f"Échec de la connexion WebSocket à {ORCHESTRATOR_WS_URL}: {e}")
        #     self.ws_client = None
        pass

    def listen_for_commands_simulation(self, command_json_string):
        """
        Simule la réception et le traitement d'une commande de l'orchestrateur.
        """
        print(f"Commande reçue (simulée via WebSocket): {command_json_string}")
        try:
            command_data = json.loads(command_json_string)
            action = command_data.get("action")
            parameters = command_data.get("parameters", {})

            if action == "quarantine_ip":
                ip = parameters.get("ip")
                if ip:
                    self.quarantine_ip(ip)
                else:
                    print("Erreur: IP manquante pour l'action quarantine_ip.")
                    self.send_response_to_orchestrator(action, {"ip": None, "status": "failure_missing_parameter_ip"})
            elif action == "kill_process":
                pid = parameters.get("pid")
                if pid is not None: # Allow PID 0, though unlikely for user processes
                    self.kill_process(pid)
                else:
                    print("Erreur: PID manquant pour l'action kill_process.")
                    self.send_response_to_orchestrator(action, {"pid": None, "status": "failure_missing_parameter_pid"})
            elif action == "rollback_snapshot":
                vm_id = parameters.get("vm_id")
                snapshot_name = parameters.get("snapshot_name", "latest_known_good")
                if vm_id:
                    self.rollback_snapshot(vm_id, snapshot_name)
                else:
                    print("Erreur: VM ID manquant pour l'action rollback_snapshot.")
                    self.send_response_to_orchestrator(action, {"vm_id": None, "status": "failure_missing_parameter_vm_id"})
            else:
                print(f"Action inconnue ou non supportée reçue: {action}")
                self.send_response_to_orchestrator(action if action else "unknown", {"parameters": parameters, "status": "failure_unknown_action"})

        except json.JSONDecodeError as e:
            print(f"Erreur de décodage JSON de la commande: {e}")
            self.send_response_to_orchestrator("json_decode_error", {"command_string": command_json_string, "status": f"failure_json_decode_error: {e}"})
        except Exception as e:
            print(f"Erreur lors du traitement de la commande {command_json_string}: {e}")
            self.send_response_to_orchestrator("command_processing_error", {"command_string": command_json_string, "status": f"failure_processing_error: {type(e).__name__} - {e}"})


    def quarantine_ip(self, ip_address):
        """Met une adresse IP en quarantaine en utilisant firewall_rules.py."""
        print(f"ACTION: Mise en quarantaine de l'IP: {ip_address}")
        status = "failure_firewall_module_load"
        try:
            # Construct path relative to the current file's directory might be more robust
            # For now, assume zt-immune-system is the root for path construction.
            firewall_script_path = "zt-immune-system/mini_agents/agent_response/firewall_rules.py"
            firewall_module_spec = importlib.util.spec_from_file_location("firewall_rules", firewall_script_path)

            if firewall_module_spec and firewall_module_spec.loader:
                 firewall_rules_module = importlib.util.module_from_spec(firewall_module_spec)
                 firewall_module_spec.loader.exec_module(firewall_rules_module)
                 # The block_ip in firewall_rules.py prints its own success/failure
                 firewall_rules_module.block_ip(ip_address)
                 # We'll assume success if no exception from exec_module or block_ip itself
                 # A real implementation would have block_ip return a status
                 status = "success_simulated_call_to_firewall_rules"
                 print(f"  IP {ip_address} bloquée (appel simulé à firewall_rules).")
            else:
                print(f"  Erreur: Impossible de charger dynamiquement firewall_rules.py depuis {firewall_script_path}.")
        except FileNotFoundError:
            print(f"  Erreur: Fichier firewall_rules.py non trouvé à {firewall_script_path}.")
            status = "failure_firewall_script_not_found"
        except Exception as e:
            print(f"  Échec de la mise en quarantaine de {ip_address}: {e}")
            status = f"failure_quarantine_exception: {type(e).__name__}"

        self.send_response_to_orchestrator("quarantine_ip", {"ip": ip_address, "status": status})

    def kill_process(self, process_id):
        """Termine un processus par son PID."""
        print(f"ACTION: Terminaison du processus PID: {process_id}")
        status = "failure_unknown"
        try:
            if not isinstance(process_id, int): # Check if it's an integer
                raise ValueError("PID doit être un entier.")
            print(f"  Processus {process_id} terminé (simulé - os.kill({process_id}, SIGKILL)).")
            status = "success_simulated"
        except ValueError as ve:
            print(f"  Échec de la terminaison du processus {process_id}: {ve}")
            status = f"failure_invalid_pid_type: {ve}"
        # ProcessLookupError and PermissionError are more for actual os.kill
        # For simulation, we'll just assume these don't happen unless explicitly simulated
        except Exception as e: # Catch any other unexpected errors
            print(f"  Échec de la terminaison du processus {process_id}: {e}")
            status = f"failure_unknown_error: {type(e).__name__}"

        self.send_response_to_orchestrator("kill_process", {"pid": process_id, "status": status})


    def rollback_snapshot(self, vm_id, snapshot_name="latest_known_good"):
        """Revient à un snapshot précédent pour une VM."""
        print(f"ACTION: Rollback du snapshot pour VM ID: {vm_id} vers '{snapshot_name}'")
        status = "failure_unknown"
        try:
            print(f"  VM {vm_id} restaurée au snapshot '{snapshot_name}' (simulé).")
            status = "success_simulated"
        except Exception as e:
            print(f"  Échec du rollback pour VM {vm_id} vers snapshot '{snapshot_name}': {e}")
            status = f"failure_unknown_error: {type(e).__name__}"

        self.send_response_to_orchestrator("rollback_snapshot", {"vm_id": vm_id, "snapshot": snapshot_name, "status": status})

    def send_response_to_orchestrator(self, action_name, response_data):
        """Envoie une réponse/confirmation à l'orchestrateur via WebSocket (simulé)."""
        payload = {
            "type": "action_response",
            "agent_id": self.agent_id,
            "original_action": action_name,
            "timestamp": time.time(),
            "response": response_data
        }
        print(f"RÉPONSE ENVOYÉE (simulé via WebSocket): {json.dumps(payload, indent=2)}")


if __name__ == "__main__":
    print("\n--- Démarrage de l'Agent de Réponse en mode direct ---")
    # Ensure firewall_rules.py exists for dynamic import test
    firewall_dir = "zt-immune-system/mini_agents/agent_response/"
    if not os.path.exists(firewall_dir):
        os.makedirs(firewall_dir)
        print(f"Created directory: {firewall_dir}")
    try:
        with open(os.path.join(firewall_dir, "firewall_rules.py"), "w") as f:
            f.write("import os\ndef block_ip(ip): print(f'  [firewall_rules.py] Simulation: os.system(iptables -A INPUT -s {ip} -j DROP)')\n")
        print(f"Fichier factice firewall_rules.py créé pour le test.")
    except IOError as e:
        print(f"Erreur IO lors de la création de firewall_rules.py de test: {e}")


    response_agent = ResponseAgent(agent_id="test_responder_01")

    print("\n--- Simulation de commandes de l'orchestrateur ---")

    cmd_quarantine = {"action": "quarantine_ip", "parameters": {"ip": "192.0.2.10"}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_quarantine))

    cmd_quarantine_bad = {"action": "quarantine_ip", "parameters": {}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_quarantine_bad))

    cmd_kill = {"action": "kill_process", "parameters": {"pid": 12345}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_kill))

    cmd_kill_invalid_pid = {"action": "kill_process", "parameters": {"pid": "not_a_pid"}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_kill_invalid_pid))

    cmd_kill_missing_pid = {"action": "kill_process", "parameters": {}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_kill_missing_pid))


    cmd_rollback = {"action": "rollback_snapshot", "parameters": {"vm_id": "vm-ubuntu-prod-01", "snapshot_name": "pre_incident_state"}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_rollback))

    cmd_unknown = {"action": "unknown_super_action", "parameters": {}}
    response_agent.listen_for_commands_simulation(json.dumps(cmd_unknown))

    cmd_bad_json = "this is not json"
    response_agent.listen_for_commands_simulation(cmd_bad_json)

    # Test dynamic loading with non-existent firewall_rules.py (temporarily rename)
    original_fw_path = os.path.join(firewall_dir, "firewall_rules.py")
    temp_fw_path = os.path.join(firewall_dir, "firewall_rules.py.bak")
    if os.path.exists(original_fw_path):
        os.rename(original_fw_path, temp_fw_path)
        print("\n--- Test avec firewall_rules.py manquant ---")
        response_agent.listen_for_commands_simulation(json.dumps(cmd_quarantine))
        os.rename(temp_fw_path, original_fw_path) # Restore
    else:
        print(f"\nSkipping missing firewall_rules.py test as {original_fw_path} was not found initially.")


    print("\n--- Fin du test direct de l'Agent de Réponse ---")
    # Cleanup dummy firewall_rules.py
    # if os.path.exists(original_fw_path):
    #     try:
    #         os.remove(original_fw_path)
    #         print("Fichier factice firewall_rules.py nettoyé.")
    #     except IOError as e:
    #         print(f"Erreur IO lors du nettoyage de firewall_rules.py: {e}")
