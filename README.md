# ZT-Immune System

Plateforme de cybersécurité Zero Trust basée sur une approche système immunitaire IA.

## Structure du projet

Voir l'arborescence détaillée dans la documentation ou ci-dessous.

## Démarrage rapide

- Python 3.9+, Node.js 16+, Docker, Kubernetes, Terraform requis.
- Voir `requirements.txt` et `dashboard/frontend/package.json` pour les dépendances.

## Architecture et Communication

Le système ZT-Immune utilise **Apache Kafka** pour la communication asynchrone entre ses différents composants, notamment entre l'IA Principale et les Mini-Agents.

### Dépendances Kafka
- **Bibliothèque Python**: `kafka-python` est requis pour l'interaction avec Kafka et est listé dans `zt-immune-system/requirements.txt`.
- **Broker Kafka**: Une instance Kafka (version 2.x ou 3.x recommandée) doit être en cours d'exécution et accessible par les composants du système.

### Flux de Communication
L'IA Principale (`ia_principale`) et les différents Mini-Agents (`mini_agents`) communiquent via des topics Kafka dédiés. Voici les principaux topics utilisés :
- `alerts_raw`: Utilisé par les agents de détection pour envoyer des alertes brutes à l'IA Principale.
- `agent_tasks_analysis`: Utilisé par l'Orchestrateur pour envoyer des tâches spécifiques aux agents d'analyse.
- `agent_tasks_detection`: (Utilisation future) Pourrait être utilisé pour des tâches de configuration ou des demandes spécifiques aux agents de détection.
- `agent_tasks_response`: (Utilisation future) Pourrait être utilisé pour coordonner les actions de réponse.
- `agent_tasks_learning`: (Utilisation future) Pourrait être utilisé pour distribuer des tâches ou des données liées à l'apprentissage continu des agents.

### Configuration de Kafka
L'adresse du broker Kafka doit être configurée pour chaque composant qui interagit avec Kafka (Orchestrateur, Agent de Détection, Agent d'Analyse, etc.). Cette configuration est généralement gérée via une variable d'environnement nommée `KAFKA_BROKER_ADDRESS`. Si cette variable n'est pas définie, la valeur par défaut est souvent `"localhost:9092"`.

## Dossiers principaux
- `ia_principale/` : Orchestrateur IA, apprentissage, contrôle Zero Trust
- `mini_agents/` : Agents autonomes (détection, réponse, analyse, déploiement, apprentissage)
- `dashboard/` : Interface admin (React + FastAPI)
- `infrastructure/` : K8s, Docker, Terraform, sécurité
- `threat_intel/` : Intelligence sur les menaces (MISP, CVE, STIX)
- `honeypots/` : Déploiement et gestion de honeypots
- `logging_monitoring/` : Elastic Stack, Wazuh
- `docs/` : Documentation technique et utilisateur 