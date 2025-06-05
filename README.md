# ZT-Immune System

Plateforme de cybersécurité Zero Trust basée sur une approche système immunitaire IA.

## Structure du projet

Voir l'arborescence détaillée dans la documentation ou ci-dessous.

## Démarrage rapide

- Python 3.9+, Node.js 16+, Docker, Kubernetes, Terraform requis.
- Voir `requirements.txt` et `dashboard/frontend/package.json` pour les dépendances.

## Dossiers principaux
- `ia_principale/` : Orchestrateur IA, apprentissage, contrôle Zero Trust
- `mini_agents/` : Agents autonomes (détection, réponse, analyse, déploiement, apprentissage)
- `dashboard/` : Interface admin (React + FastAPI)
- `infrastructure/` : K8s, Docker, Terraform, sécurité
- `threat_intel/` : Intelligence sur les menaces (MISP, CVE, STIX)
- `honeypots/` : Déploiement et gestion de honeypots
- `logging_monitoring/` : Elastic Stack, Wazuh
- `docs/` : Documentation technique et utilisateur 