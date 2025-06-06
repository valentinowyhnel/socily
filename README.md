# ZT-Immune System

Plateforme de cybersécurité **Zero Trust** basée sur une approche système immunitaire **IA**.

---

![ZT-Immune Logo](./public/assets/logo512.png)

## 🌐 Structure du projet

Voir l'arborescence détaillée dans la documentation ou ci-dessous.

## ⚡ Démarrage rapide

- Requis : `Python 3.9+`, `Node.js 16+`, `Docker`, `Kubernetes`, `Terraform`
- Vérifiez les dépendances dans :
  - `zt-immune-system/requirements.txt`
  - `dashboard/frontend/package.json`

---

## 🧠 Architecture et Communication

Le système **ZT-Immune** utilise **Apache Kafka** pour la communication asynchrone entre ses différents composants, notamment entre l'**IA Principale** et les **Mini-Agents**.

### 📦 Dépendances Kafka

- **Librairie Python** : [`kafka-python`](https://pypi.org/project/kafka-python/) (déclarée dans `requirements.txt`)
- **Kafka Broker** : Une instance Kafka (v2.x ou v3.x recommandée) doit être disponible

### 🔁 Flux de Communication

| Topic Kafka             | Rôle                                                                 |
|------------------------|----------------------------------------------------------------------|
| `alerts_raw`           | Alertes brutes envoyées par les agents de détection à l'IA Principale |
| `agent_tasks_analysis` | Tâches d'analyse envoyées aux mini-agents                           |
| `agent_tasks_detection`| (Futur) Configuration ou commandes aux agents de détection           |
| `agent_tasks_response` | (Futur) Coordination des réponses                                    |
| `agent_tasks_learning` | (Futur) Apprentissage continu distribué                             |

### ⚙️ Configuration Kafka

Chaque composant utilisant Kafka doit configurer la variable d'environnement `KAFKA_BROKER_ADDRESS`. Par défaut :
```bash
KAFKA_BROKER_ADDRESS=localhost:9092
```

---

## 🗂️ Dossiers principaux

| Dossier                   | Description                                                         |
|--------------------------|---------------------------------------------------------------------|
| `ia_principale/`         | Orchestrateur IA, contrôle Zero Trust, apprentissage                |
| `mini_agents/`           | Agents autonomes (détection, réponse, analyse, apprentissage, etc.) |
| `dashboard/`             | Interface admin (React, xterm.js, FastAPI, auth, voice+click UI)   |
| `infrastructure/`        | Docker, K8s, Terraform, réseau, sécurité                            |
| `threat_intel/`          | Intelligence sur les menaces (MISP, CVE, STIX, Yara)                |
| `honeypots/`             | Déploiement et gestion des honeypots                                |
| `logging_monitoring/`    | Centralisation logs/alertes avec Elastic Stack, Loki, Wazuh         |
| `docs/`                  | Documentation technique et utilisateur                              |

---

## 🎨 Ressources UI/UX (frontend/public)

| Fichier                      | Utilité                                         |
|-----------------------------|--------------------------------------------------|
| `index.html`                | Point d'entrée React                            |
| `favicon.ico`               | Icône de l'onglet navigateur                    |
| `manifest.json`             | Métadonnées PWA                                 |
| `robots.txt`                | Configuration SEO                               |
| `logo512.png`               | Logo principal haute résolution                 |
| `logo192.png`               | Logo mobile ou favicon                          |
| `assets/ai-avatar.png`      | Avatar IA (assistant vocal et visuel)           |
| `assets/zero-trust-diagram.png` | Diagramme de l'architecture système         |
| `assets/fonts/Inter.woff2`  | Typographie personnalisée                       |
| `assets/docs/whitepaper.pdf`| Document technique à distribuer                 |

---

## 🧩 Interface Utilisateur (Dashboard React)

- Authentification sécurisée (JWT via FastAPI)
- Console interactive (xterm.js)
- Dashboard de statut en temps réel (Mini-Agents, Alertes, Logs)
- Assistant IA avec validation humaine (clic ou commande vocale)
- UI moderne stylisée avec **Shadcn UI** + **Tailwind CSS**

---

> Projet conçu pour fournir une **cybersécurité adaptative, autonome, et auditable**, fondée sur une synergie IA-Humain.
