# 🛡️ ZT-Immune System

![Gemini_Generated_Image_lu22mclu22mclu22](https://github.com/user-attachments/assets/74e5e571-6af4-4afc-8353-bf962c4012d0)



**Plateforme de cybersécurité Zero Trust inspirée du système immunitaire humain et propulsée par une IA collaborative.**

---

![Langages](https://img.shields.io/badge/langages-Python%20%7C%20JavaScript-blue?style=for-the-badge&logo=python&logoColor=white)
![Frontend](https://img.shields.io/badge/frontend-React%20%7C%20xterm.js-61dafb?style=for-the-badge&logo=react)
![Backend](https://img.shields.io/badge/backend-FastAPI%20%7C%20Kafka-009688?style=for-the-badge&logo=fastapi)
![DevOps](https://img.shields.io/badge/devops-Kubernetes%20%7C%20Docker%20%7C%20Terraform-purple?style=for-the-badge&logo=docker)
![Monitoring](https://img.shields.io/badge/monitoring-Grafana%20%7C%20Loki-orange?style=for-the-badge&logo=grafana)
![License](https://img.shields.io/github/license/zt-immune/zt-immune-system?style=for-the-badge)
![Open Source](https://img.shields.io/badge/open--source-yes-brightgreen?style=for-the-badge&logo=github)
![Contributeurs bienvenus](https://img.shields.io/badge/contributeurs-bienvenus-yellow?style=for-the-badge&logo=github)
[![Open Source Helpers](https://www.codetriage.com/valentinowyhnel/socily/badges/users.svg)](https://www.codetriage.com/valentinowyhnel/socily)
---

## 🚀 Démarrage rapide

> *Prérequis* : `Python 3.9+`, `Node.js 16+`, `Docker`, `Kubernetes`, `Terraform`

Installez les dépendances :
- Backend Python : `zt-immune-system/requirements.txt`
- Frontend React : `dashboard/frontend/package.json`

---

## 🧬 Architecture et Communication

Le système utilise **Apache Kafka** comme bus de messages asynchrone entre :
- **IA Principale** (orchestrateur & décision)
- **Mini-Agents** (détection, réponse, apprentissage, déploiement)

### 📡 Kafka - Topics principaux

| Topic Kafka             | Fonction                                                          |
|------------------------|-------------------------------------------------------------------|
| `alerts_raw`           | Alertes des agents envoyées à l'IA principale                     |
| `agent_tasks_analysis` | Tâches analytiques envoyées par l'orchestrateur                   |
| `agent_tasks_detection`| (à venir) Configuration ou consignes vers les agents de détection |
| `agent_tasks_response` | (à venir) Coordination des réponses distribuées                   |
| `agent_tasks_learning` | (à venir) Apprentissage partagé entre agents                      |

### ⚙️ Configuration Kafka

Définir la variable d’environnement :
```bash
KAFKA_BROKER_ADDRESS=localhost:9092
