# firewall_rules.py
# - Gestion dynamique avec nftables :
#   def block_ip(ip):
#     os.system(f"nft add rule filter input ip saddr {ip} drop")
# Appelé par responder.py

import os
import re # Pour la validation basique de l'IP

print("Initialisation du logger pour firewall_rules.py (placeholder)")

# Constantes pour nftables (pourraient être configurées)
NFT_TABLE_FAMILY = "inet" # ou "ip", "ip6"
NFT_TABLE_NAME = "filter" # Nom de la table existante
NFT_CHAIN_NAME = "input"  # Nom de la chaîne existante où ajouter la règle

def is_valid_ipv4(ip_string):
    """Vérifie basiquement si la chaîne ressemble à une adresse IPv4."""
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if pattern.match(ip_string):
        parts = ip_string.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False

def is_valid_ipv6(ip_string):
    """Vérifie basiquement si la chaîne ressemble à une adresse IPv6."""
    # Validation simpliste. Le module ipaddress est bien meilleur.
    if not isinstance(ip_string, str):
        return False
    if ip_string.count('::') <= 1: # Au plus un '::'
        parts = ip_string.split(':')
        if len(parts) <= 8: # Max 8 groupes hex
            hex_chars = "0123456789abcdefABCDEF"
            for part in parts:
                if not (0 <= len(part) <= 4 and all(c in hex_chars for c in part)):
                    if part == '' and ip_string.count('::') == 1: # partie vide permise avec ::
                        continue
                    return False
            return True
    return False


def block_ip(ip_address):
    """
    Bloque une adresse IP en ajoutant une règle à nftables.
    Utilise os.system pour simuler l'interaction avec la commande nft.
    ATTENTION: os.system est généralement déconseillé.
    """
    print(f"  [firewall_rules.py] Tentative de blocage de l'IP: {ip_address} en utilisant nftables (simulé).")

    is_ipv6 = is_valid_ipv6(ip_address)
    is_ipv4 = is_valid_ipv4(ip_address)

    if not (is_ipv4 or is_ipv6):
        print(f"    ERREUR: Adresse IP invalide fournie: {ip_address}. Blocage annulé.")
        return False

    address_family_spec = ""
    if is_ipv6:
        address_family_spec = "ip6 " # 'ip6 saddr ...'
    elif is_ipv4:
        address_family_spec = "ip "  # 'ip saddr ...'

    # nft add rule [inet|ip|ip6] <table_name> <chain_name> [ip|ip6] saddr <ip_address> drop
    nft_command = f"nft add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {NFT_CHAIN_NAME} {address_family_spec}saddr {ip_address} drop"

    print(f"    EXÉCUTION (simulée): {nft_command}")

    try:
        if ip_address == "error_ip_simulation":
            status_code = 1
            print(f"    ÉCHEC SIMULÉ de la commande nft (code de retour: {status_code}).")
        else:
            status_code = 0
            print(f"    Commande nft exécutée avec succès (simulé - code de retour: {status_code}).")

        if status_code == 0:
            print(f"    IP {ip_address} bloquée avec succès (simulé).")
            return True
        else:
            print(f"    Échec du blocage de l'IP {ip_address} (simulé - la commande nft a échoué).")
            return False

    except Exception as e:
        print(f"    ERREUR EXCEPTIONNELLE lors de la tentative d'exécution de la commande nft: {e}")
        return False

if __name__ == "__main__":
    print("\n--- Test direct du module firewall_rules.py ---")

    print("\n--- Test de blocage d'IPs valides ---")
    block_ip("192.0.2.1")
    block_ip("2001:db8::1")
    block_ip("::1") # Loopback IPv6
    block_ip("fd00::1234") # ULA IPv6

    print("\n--- Test de blocage d'IPs invalides ---")
    block_ip("not.an.ip")
    block_ip("192.168.1.300")
    block_ip("12345::ffff::1")
    block_ip("abcd:efgh::1")
    block_ip("2001:db8:::1") # Double '::'
    block_ip("1.2.3.4.5")
    block_ip("1::2::3")

    print("\n--- Test de simulation d'erreur de commande nft ---")
    block_ip("error_ip_simulation")

    print("\n--- Fin du test direct de firewall_rules.py ---")
