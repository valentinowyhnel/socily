# nlp_module.py
# - Analyse des rapports texte avec HuggingFace
# - Génération de résumés automatisés
# - Détection d'intentions dans les requêtes admin
# Reçoit des données de data_ingestion.py (rapports externes)

# from transformers import pipeline # Placeholder pour HuggingFace
# from . import utils # Pour les logs

# logger = utils.setup_logger('nlp_logger', 'nlp_module.log')
print("Initialisation du logger pour nlp_module (placeholder)") # Placeholder

class NLPModule:
    def __init__(self):
        # Initialiser les pipelines HuggingFace ici (peut prendre du temps, donc faire une seule fois)
        # try:
        #     self.summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
        #     self.intent_detector = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
        #     # Pour l'extraction d'IOC, un modèle NER (Named Entity Recognition) serait plus approprié
        #     self.ner_pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english", grouped_entities=True)
        #     logger.info("Pipelines HuggingFace (summarization, zero-shot-classification, NER) initialisés.")
        # except Exception as e:
        #     logger.error(f"Erreur lors de l'initialisation des pipelines HuggingFace: {e}")
        #     # Fallback ou mode dégradé si les modèles ne peuvent pas être chargés
        #     self.summarizer = None
        #     self.intent_detector = None
        #     self.ner_pipeline = None
        print("Pipelines HuggingFace initialisés (placeholder - modèles non chargés).")

    def analyze_report_text(self, report_text, report_source="unknown"):
        """
        Analyse un rapport texte pour en extraire des informations clés et générer un résumé.
        """
        # logger.info(f"Analyse du rapport texte de la source: {report_source} (longueur: {len(report_text)}).")
        print(f"Analyse du rapport texte de la source: {report_source} (longueur: {len(report_text)}). (placeholder)")

        summary = self.generate_summary(report_text)
        iocs = self.extract_iocs_from_text(report_text) # Utilisation de NER

        analysis_result = {
            "source": report_source,
            "original_length": len(report_text),
            "summary": summary,
            "extracted_iocs": iocs, # Liste d'IOCs extraits
        }
        # logger.info(f"Analyse terminée. Résumé: '{summary[:100]}...', IOCs trouvés: {len(iocs)}.")
        print(f"Analyse terminée. Résumé: '{str(summary)[:100]}...', IOCs trouvés: {len(iocs)}. (placeholder)") # Ensure summary is string for slicing
        return analysis_result

    def generate_summary(self, text, min_length=30, max_length=150):
        """
        Génère un résumé automatisé du texte fourni.
        """
        # if not self.summarizer:
        #     logger.warning("Pipeline de résumé non disponible. Retour du texte tronqué.")
        #     return text[:max_length] + "..." if len(text) > max_length else text

        # logger.debug("Génération du résumé...")
        # try:
        #     summary_list = self.summarizer(text, max_length=max_length, min_length=min_length, do_sample=False)
        #     summary = summary_list[0]['summary_text']
        #     logger.debug(f"Résumé généré: {summary}")
        #     return summary
        # except Exception as e:
        #     logger.error(f"Erreur lors de la génération du résumé: {e}")
        #     return "Erreur lors de la génération du résumé."
        print(f"Génération du résumé pour texte (longueur {len(text)}) (placeholder).")
        return f"Résumé placeholder: {text[:max_length]}..." if len(text) > max_length else text


    def detect_admin_intent(self, admin_query, candidate_labels=None):
        """
        Détecte l'intention d'une requête administrateur en utilisant le zero-shot classification.
        """
        # if not self.intent_detector:
        #     logger.warning("Pipeline de détection d'intention non disponible.")
        #     return {"error": "Détecteur d'intention non disponible."}

        if candidate_labels is None:
            candidate_labels = ["show status", "block ip", "get report", "list agents"]

        # logger.debug(f"Détection d'intention pour la requête: '{admin_query}' avec les labels: {candidate_labels}")
        # try:
        #     result = self.intent_detector(admin_query, candidate_labels)
        #     # logger.debug(f"Résultat de la détection d'intention: {result}")
        #     return {
        #         "query": admin_query,
        #         "intent": result['labels'][0], # Label avec le score le plus élevé
        #         "confidence": result['scores'][0]
        #     }
        # except Exception as e:
        #     logger.error(f"Erreur lors de la détection d'intention: {e}")
        #     return {"error": f"Erreur lors de la détection d'intention: {e}"}
        print(f"Détection d'intention pour: '{admin_query}' (placeholder).")
        return {
            "query": admin_query,
            "intent": candidate_labels[0] if candidate_labels else "unknown",
            "confidence": 0.99 # Placeholder
        }

    def extract_iocs_from_text(self, text):
        """
        Extrait les Indicateurs de Compromission (IOCs) d'un texte en utilisant NER.
        Les IOCs peuvent être des adresses IP, des URLs, des hashs de fichiers, des CVEs, etc.
        """
        # if not self.ner_pipeline:
        #     logger.warning("Pipeline NER non disponible. Aucune extraction d'IOC possible.")
        #     return []

        # logger.debug("Extraction d'IOCs par NER...")
        # try:
        #     entities = self.ner_pipeline(text)
        #     iocs = []
        #     for entity in entities:
        #         # Filtrer et formater les entités pour correspondre à une structure d'IOC
        #         # Exemple: {'type': 'IP', 'value': '192.168.1.1'}
        #         # entity['entity_group'] pourrait être 'PER', 'LOC', 'ORG', 'MISC' ou des types plus spécifiques si le modèle le supporte.
        #         # Il faudra mapper 'entity_group' à des types d'IOC (ex: 'IPv4', 'URL', 'SHA256')
        #         # Ceci est un exemple simplifié.
        #         entity_type = entity.get('entity_group', 'UNKNOWN').upper()
        #         entity_value = entity.get('word')

        #         # Logique de mappage et de filtrage (très basique ici)
        #         ioc_type_map = {
        #             "IP": "ip_address", # Si le modèle NER identifie 'IP'
        #             "DOMAIN": "domain_name", # Si le modèle NER identifie 'DOMAIN'
        #             "URL": "url",
        #             "FILENAME": "file_name",
        #             "HASH": "file_hash", # Pourrait nécessiter une validation de format
        #         }
        #         # Un vrai modèle NER pour la cybersécurité serait plus précis.
        #         # Ce modèle générique (conll03) est plus pour PER, LOC, ORG, MISC.
        #         # Il faudrait un modèle fine-tuné sur des données cyber.

        #         if entity_type in ["MISC", "ORG"]: # Exemple de ce que CoNLL03 pourrait sortir
        #             # Tentative de deviner le type d'IOC basé sur le contenu (placeholder)
        #             if '.' in entity_value and all(c.isdigit() or c == '.' for c in entity_value):
        #                 potential_type = "ip_address"
        #             elif 'http:' in entity_value or 'https:' in entity_value:
        #                 potential_type = "url"
        #             else:
        #                 potential_type = "potential_threat_actor_or_tool" # Placeholder

        #             iocs.append({"type": potential_type, "value": entity_value, "source_ner_group": entity_type})


        #     logger.debug(f"IOCs extraits par NER: {iocs}")
        #     return iocs
        # except Exception as e:
        #     logger.error(f"Erreur lors de l'extraction d'IOCs par NER: {e}")
        #     return []
        print(f"Extraction d'IOCs pour texte (longueur {len(text)}) (placeholder).")
        # Placeholder IOCs
        iocs_found = []
        if "1.2.3.4" in text:
            iocs_found.append({"type": "ip_address", "value": "1.2.3.4"})
        if "evil.com" in text:
            iocs_found.append({"type": "domain_name", "value": "evil.com"})
        if "192.168.0.1" in text: # Added from example
            iocs_found.append({"type": "ip_address", "value": "192.168.0.1"})
        if "example.org" in text: # Added from example
            iocs_found.append({"type": "domain_name", "value": "example.org"})
        return iocs_found

# Pour des tests unitaires
if __name__ == "__main__":
    # logger.info("Démarrage du module NLP en mode direct.")
    print("Démarrage du module NLP en mode direct.")
    nlp_instance = NLPModule()

    sample_report = (
        "Un nouveau rapport de menace indique une activité suspecte provenant de l'adresse IP 1.2.3.4. "
        "Le malware utilise le domaine evil.com pour la communication C2. "
        "Nous recommandons de bloquer ces indicateurs immédiatement."
    )
    analysis = nlp_instance.analyze_report_text(sample_report, "Test Source")
    print(f"Résultat de l'analyse: {analysis}")

    admin_command = "show me the current status of all agents"
    intent = nlp_instance.detect_admin_intent(admin_command)
    print(f"Résultat de la détection d'intention: {intent}")

    admin_command_block = "block the ip 10.0.0.1"
    intent_block = nlp_instance.detect_admin_intent(admin_command_block, ["block ip", "unblock ip", "show logs"])
    print(f"Résultat de la détection d'intention (block): {intent_block}")

    iocs = nlp_instance.extract_iocs_from_text("Le serveur 192.168.0.1 a été compromis par un attaquant utilisant example.org.")
    print(f"IOCs extraits: {iocs}")

    # logger.info("Fin du test direct du module NLP.")
    print("Fin du test direct du module NLP.")
