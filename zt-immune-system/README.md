# ZT-Immune System

**Plateforme de cybersécurité Zero Trust basée sur une approche système immunitaire IA.**

## 1. Project Overview

Le ZT-Immune System est une plateforme de cybersécurité avancée conçue pour implémenter les principes du Zero Trust au sein d'une infrastructure informatique. Elle s'inspire du système immunitaire biologique pour créer un écosystème de sécurité adaptatif, capable de détecter, analyser et répondre de manière autonome aux menaces émergentes et sophistiquées.

**Problème Résolu**: Les approches de sécurité traditionnelles basées sur le périmètre ne sont plus suffisantes face aux menaces modernes (attaques internes, APTs, zero-day exploits). Le ZT-Immune System vise à fournir une sécurité granulaire et dynamique où la confiance n'est jamais implicite.

**Approche Clé**:
- **Zero Trust**: "Ne jamais faire confiance, toujours vérifier." Chaque requête, utilisateur et appareil est validé avant d'accorder l'accès aux ressources.
- **Intelligence Artificielle (IA)**: Des modèles d'IA sont utilisés pour l'analyse comportementale, la détection d'anomalies, la corrélation d'événements et l'aide à la décision.
- **Agents Autonomes (Mini-Agents)**: Un réseau d'agents spécialisés (détection, analyse, réponse, apprentissage) opère de manière distribuée pour surveiller et protéger les actifs.

## 2. System Architecture

Le ZT-Immune System est composé de plusieurs modules interconnectés qui collaborent pour assurer la sécurité de l'infrastructure.

[System Architecture Diagram Placeholder - Visual diagram to be added, e.g., in `docs/diagrams/system_architecture.png` or embedded here if simple enough.]

### Composants Principaux:

*   **Dashboard Frontend (`dashboard/frontend/`)**: Interface utilisateur web (React) pour la visualisation des alertes, l'état du système, la gestion des agents, la configuration des politiques et l'interaction avec l'IA (approbation de commandes, console).
*   **Dashboard Backend (`dashboard/backend/`)**: API (FastAPI) fournissant les données au frontend, gérant l'authentification des utilisateurs et servant de point d'entrée pour les commandes manuelles.
*   **IA Principale (`ia_principale/`)**: Le "cerveau" du système. Comprend l'Orchestrateur, les modules d'analyse de menaces, les modèles d'apprentissage machine, et le moteur de décision Zero Trust. Il reçoit les alertes, évalue les menaces, et coordonne les actions des Mini-Agents.
*   **Mini-Agents (`mini_agents/`)**: Agents logiciels légers et spécialisés déployés sur les endpoints, serveurs, ou segments réseau. Types d'agents :
    *   `agent_detection`: Surveille les activités suspectes, collecte les logs, utilise des règles (YARA, Sigma) pour générer des alertes.
    *   `agent_analysis`: Effectue des analyses approfondies sur des artefacts ou des événements suspects (sandboxing, analyse de malware).
    *   `agent_response`: Exécute des actions de remédiation (isoler un hôte, bloquer une IP).
    *   `agent_learning`: Collecte des données pour l'entraînement des modèles d'IA et peut effectuer un apprentissage local.

### Communication Interne:

Le système ZT-Immune utilise **Apache Kafka** pour la communication asynchrone et résiliente entre ses différents composants, notamment entre l'IA Principale et les Mini-Agents.

*   **Dépendances Kafka**:
    *   Bibliothèque Python: `kafka-python` (listé dans `zt-immune-system/requirements.txt`).
    *   Bibliothèque Node.js (si des composants Node.js interagissent directement avec Kafka): `kafkajs` (non utilisé actuellement dans les composants décrits).
    *   Broker Kafka: Une instance Kafka (version 2.x ou 3.x recommandée) doit être en cours d'exécution.
*   **Flux de Communication (Topics Kafka clés)**:
    *   `alerts_raw`: Les agents de détection envoient des alertes brutes à l'IA Principale.
    *   `agent_tasks_analysis`: L'Orchestrateur envoie des tâches spécifiques aux agents d'analyse.
    *   `agent_tasks_detection`: (Utilisation future) Pourrait être utilisé pour des tâches de configuration ou des demandes spécifiques aux agents de détection.
    *   `agent_tasks_response`: (Utilisation future) L'Orchestrateur envoie des commandes de réponse aux agents de réponse.
    *   `agent_learning_data`: (Utilisation future) Les agents envoient des données pertinentes pour l'apprentissage continu à l'IA Principale.
*   **Configuration de Kafka**:
    *   L'adresse du broker Kafka est configurée via la variable d'environnement `KAFKA_BROKER_ADDRESS` (défaut: `"localhost:9092"`) pour chaque composant concerné.

## 3. Technologies Utilisées

*   **Backend & Orchestration**:
    *   Python (Langage principal)
    *   FastAPI (Framework API pour le backend du dashboard et potentiellement pour les services internes de l'IA)
    *   Apache Kafka (Bus de messages pour la communication asynchrone)
*   **Frontend Dashboard**:
    *   React.js (Bibliothèque JavaScript pour l'interface utilisateur)
    *   Vite (Outil de build et serveur de développement frontend)
    *   xterm.js (Pour le terminal interactif dans le dashboard)
    *   Shadcn UI (Collection de composants UI réutilisables)
    *   Tailwind CSS (Framework CSS orienté utilitaires)
*   **Intelligence Artificielle & Machine Learning**:
    *   Python
    *   Scikit-learn (Bibliothèque ML générale - placeholder)
    *   TensorFlow / PyTorch (Frameworks de Deep Learning - placeholder, à choisir selon les besoins)
*   **Conteneurisation & Orchestration**:
    *   Docker
    *   Kubernetes (pour le déploiement et la gestion à l'échelle - placeholder)
*   **Infrastructure as Code (IaC)**:
    *   Terraform (pour la gestion de l'infrastructure cloud - placeholder)
*   **Threat Intelligence & Monitoring (Intégrations prévues/possibles)**:
    *   MISP (Plateforme de partage d'informations sur les menaces - placeholder)
    *   ELK Stack (Elasticsearch, Logstash, Kibana) / OpenSearch (Logging & Monitoring - placeholder)
    *   Wazuh (Plateforme de sécurité des endpoints, SIEM - placeholder)

## 4. Prérequis

Avant de commencer, assurez-vous d'avoir les éléments suivants installés sur votre système :

*   **Node.js**: v18.x ou plus récent (pour le frontend).
*   **Python**: v3.9 ou plus récent (pour le backend et les composants IA).
*   **Pip**: Pour la gestion des paquets Python.
*   **Docker & Docker Compose**: Pour exécuter des services conteneurisés, notamment Kafka.
*   **Kubernetes (Optionnel, pour déploiement avancé)**: Minikube, kind, k3s, ou un cluster cloud.
*   **Terraform (Optionnel, pour IaC)**: Si vous gérez l'infrastructure via Terraform.
*   **Broker Apache Kafka**: Une instance Kafka fonctionnelle (peut être lancée via Docker Compose pour le développement).
*   **Git**: Pour cloner le dépôt.

## 5. Installation (Instructions Générales)

1.  **Cloner le Dépôt**:
    ```bash
    git clone https://github.com/your-username/zt-immune-system.git # Remplacez par l'URL réelle
    cd zt-immune-system
    ```
2.  **Configuration de Kafka**:
    *   Assurez-vous qu'une instance Kafka est accessible. Pour le développement local, un fichier `docker-compose.yml` (à créer dans `infrastructure/kafka/` par exemple) peut être utilisé pour démarrer Kafka et Zookeeper.
3.  **Installation Backend (`ia_principale/` et `dashboard/backend/`)**:
    *   Naviguez vers le répertoire du composant (ex: `cd ia_principale`).
    *   Créez et activez un environnement virtuel Python :
        ```bash
        python -m venv venv
        source venv/bin/activate  # Sur Windows: venv\Scripts\activate
        ```
    *   Installez les dépendances Python :
        ```bash
        pip install -r requirements.txt
        ```
    *   Répétez pour chaque composant backend Python.
4.  **Installation Frontend (`dashboard/frontend/`)**:
    *   Naviguez vers `cd dashboard/frontend`.
    *   Installez les dépendances Node.js :
        ```bash
        npm install
        # ou yarn install
        ```
5.  **Configuration des Composants IA (Mini-Agents)**:
    *   Suivez les instructions spécifiques dans les README de chaque agent (ex: `mini_agents/agent_detection/README.md`).

Consultez les fichiers README spécifiques à chaque module pour des instructions d'installation et de configuration détaillées.

## 6. Configuration

Les variables d'environnement clés suivantes sont utilisées pour configurer le système :

*   **`KAFKA_BROKER_ADDRESS`**: Adresse du (des) broker(s) Kafka.
    *   Exemple: `localhost:9092`
    *   Utilisé par: `ia_principale/orchestrator.py`, `ia_principale/main.py` (pour le consommateur d'alertes), `mini_agents/*/*.py`.
*   **`API_PORT` (pour `dashboard/backend/app.py`)**: Port sur lequel le backend FastAPI du dashboard écoute.
    *   Exemple: `8001` (défini dans `app.py` pour uvicorn)
*   **`FRONTEND_PORT` (pour `dashboard/frontend/`)**: Port sur lequel le serveur de développement Vite du frontend écoute.
    *   Exemple: `3000` (défini dans `vite.config.js`)
*   **`SECRET_KEY` (pour `dashboard/backend/auth.py`)**: Clé secrète pour la signature des tokens JWT. **DOIT être changée pour la production.**

Ces variables peuvent être définies dans votre environnement système, dans des fichiers `.env` (nécessiterait `python-dotenv` pour le backend, ou une gestion via Vite pour le frontend), ou lors du lancement des conteneurs Docker / manifestes Kubernetes.

## 7. Exécution du Système (Exemples Locaux)

1.  **Démarrer Kafka**:
    *   Si vous utilisez Docker Compose (exemple) :
        ```bash
        # (depuis le répertoire contenant votre docker-compose.yml pour Kafka)
        docker-compose up -d
        ```
2.  **Démarrer le Backend du Dashboard**:
    ```bash
    cd zt-immune-system/dashboard/backend
    # source ../../ia_principale/venv/bin/activate # Si venv est partagé ou activez son propre venv
    uvicorn app:app --host 0.0.0.0 --port 8001 --reload
    # (Assurez-vous que KAFKA_BROKER_ADDRESS est défini dans votre environnement)
    ```
3.  **Démarrer le Frontend du Dashboard**:
    ```bash
    cd zt-immune-system/dashboard/frontend
    npm run dev
    # (Le frontend se connectera au backend sur le port 8001 par défaut)
    ```
4.  **Démarrer l'IA Principale**:
    ```bash
    cd zt-immune-system/ia_principale
    # source venv/bin/activate
    python main.py
    # (Assurez-vous que KAFKA_BROKER_ADDRESS est défini)
    ```
5.  **Démarrer les Mini-Agents** (exemple pour l'agent de détection):
    ```bash
    cd zt-immune-system/mini_agents/agent_detection
    # Assurez-vous que KAFKA_BROKER_ADDRESS est défini et ia_principale est dans PYTHONPATH si besoin
    python detector.py
    ```
    *   Répétez pour les autres agents actifs (ex: `agent_analysis/analyzer.py`).

Consultez les README spécifiques pour des options de lancement plus avancées ou pour le déploiement en production.

## 8. Directory Structure

Voici un aperçu de la structure des dossiers principaux du projet :

*   **`ia_principale/`**: Orchestrateur IA, modules d'apprentissage, moteur de décision Zero Trust, consommateur d'alertes.
    *   `communication/`: Clients Kafka, etc.
    *   `event_processing/`: Logique de traitement des événements.
    *   `models/`: Modèles de données, modèles ML (potentiellement).
*   **`mini_agents/`**: Agents autonomes pour des tâches spécifiques.
    *   `agent_analysis/`: Agent pour l'analyse approfondie des menaces.
    *   `agent_detection/`: Agent pour la détection d'activités suspectes.
    *   `agent_response/`: (Placeholder) Agent pour exécuter des actions de remédiation.
    *   `agent_learning/`: (Placeholder) Agent pour l'apprentissage distribué.
*   **`dashboard/`**: Interface utilisateur et son backend.
    *   `backend/`: API FastAPI, gestion des WebSockets, authentification.
    *   `frontend/`: Application React (Vite), composants UI (Shadcn), services.
        *   `public/`: Assets statiques (index.html, icons, etc.).
        *   `src/`: Code source React.
*   **`infrastructure/`**: (Placeholder) Configurations pour Docker, Kubernetes, Terraform, Kafka (ex: `docker-compose.yml`).
*   **`threat_intel/`**: (Placeholder) Scripts ou modules pour l'intégration de flux d'intelligence sur les menaces (MISP, CVE, STIX).
*   **`honeypots/`**: (Placeholder) Configurations ou code pour le déploiement et la gestion de honeypots.
*   **`logging_monitoring/`**: (Placeholder) Configurations pour des outils comme ELK Stack ou Wazuh.
*   **`docs/`**: Documentation technique, utilisateur, et architecture.
*   **`tests/`**: (Placeholder) Tests unitaires, d'intégration, et end-to-end.
*   `.gitignore`, `LICENSE`, `README.md` (ce fichier).

## 9. Contributing

Les contributions sont les bienvenues ! Que ce soit pour signaler des bugs, proposer des améliorations, ou soumettre du code, votre aide est appréciée.
Veuillez consulter `CONTRIBUTING.md` (fichier à créer) pour les directives de contribution et le processus de développement.
Vous pouvez également ouvrir une "Issue" sur la page GitHub du projet pour discuter des changements que vous aimeriez apporter.

## 10. License

Ce projet est sous licence MIT.
Consultez le fichier `LICENSE` (à créer à la racine du projet) pour plus de détails.

---
*Dernière mise à jour de ce README : {{YYYY-MM-DD}}*
