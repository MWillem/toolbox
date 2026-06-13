GUIDES = {
    "mapping": {
        "title": "MAPPAGE RESEAU",
        "why": "Identifier les machines actives avant d'étudier leur surface exposée.",
        "when": "Au début d'un audit, après avoir défini et fait autoriser le périmètre.",
        "how": "Nmap envoie des sondes de découverte avec -sn. Sans Nmap, un ping sert de repli.",
        "gain": "Une liste d'hôtes à examiner, pas une preuve de vulnérabilité.",
    },
    "ports": {
        "title": "SCAN DE PORTS",
        "why": "Repérer les services réseau accessibles et leurs versions éventuelles.",
        "when": "Après la découverte des hôtes, sur une cible explicitement autorisée.",
        "how": "Nmap -sV teste les ports demandés et tente d'identifier les services.",
        "gain": "Une carte de la surface d'attaque à confronter aux besoins métier.",
    },
    "password": {
        "title": "RESISTANCE DES MOTS DE PASSE",
        "why": "Comprendre pourquoi un mot de passe faible peut être retrouvé hors ligne.",
        "when": "Lors d'un audit de politique de mots de passe ou dans un lab local.",
        "how": "Le lab compare un hash local à une liste bornée de candidats. Aucun service distant n'est attaqué.",
        "gain": "Une mesure concrète du coût d'une attaque par dictionnaire et des recommandations.",
    },
    "payload": {
        "title": "ANALYSE DE PAYLOAD",
        "why": "Comprendre ce qu'un payload transporte et quels indices permettent de le détecter.",
        "when": "En analyse de malware, réponse à incident ou laboratoire isolé.",
        "how": "La toolbox calcule une empreinte, recherche des indicateurs et simule un dépôt sans exécution.",
        "gain": "Des réflexes d'analyse et de traçabilité sans déployer de backdoor.",
    },
    "reports": {
        "title": "GESTION DES RAPPORTS",
        "why": "Transformer des résultats techniques en preuves et recommandations exploitables.",
        "when": "Pendant tout l'audit, puis lors de la restitution.",
        "how": "Consulter, fusionner ou supprimer les rapports Markdown depuis l'outil.",
        "gain": "Une chronologie lisible des actions, observations et limites.",
    },
    "mission": {
        "title": "MISSION GUIDEE",
        "why": "Relier les outils dans l'ordre réel d'un audit plutôt que produire des résultats isolés.",
        "when": "Pour apprendre la méthode ou conduire une première analyse structurée.",
        "how": "La mission conserve le périmètre, les hôtes, la cible, les services et les recommandations.",
        "gain": "Une session réutilisable et un rapport final cohérent.",
    },
    "watchdog": {
        "title": "MODE WATCHDOG",
        "why": "Apprendre à corréler plusieurs indices ou présenter un actif autorisé.",
        "when": "Pour une enquête fictive ou la démonstration d'un appareil du réseau privé.",
        "how": "Le mode propose un scénario local, un profil d'appareil et un profil public passif.",
        "gain": "Une expérience narrative qui conserve les preuves, la confiance et les limites.",
    },
    "logs": {
        "title": "ANALYSE DE JOURNAUX",
        "why": "Détecter des événements qui deviennent suspects lorsqu'ils sont corrélés.",
        "when": "En supervision, investigation ou réponse à incident.",
        "how": "La toolbox recherche les échecs répétés, succès associés et requêtes web sensibles.",
        "gain": "Des constats priorisés à vérifier avec le contexte et les autres sources.",
    },
    "http_lab": {
        "title": "LAB HTTP LOCAL",
        "why": "Disposer d'une cible stable où les défauts observés sont connus et sans danger.",
        "when": "Pour apprendre le scan local et l'analyse des en-têtes sans dépendre d'un site tiers.",
        "how": "Un serveur sur 127.0.0.1:8088 omet volontairement plusieurs en-têtes de sécurité.",
        "gain": "Un diagnostic reproductible et une comparaison possible après correction.",
    },
    "permissions": {
        "title": "PERMISSIONS ET CONFIGURATION",
        "why": "Réduire l'exposition des fichiers sensibles et les détournements de configuration.",
        "when": "Lors d'un audit local, d'une revue de poste ou avant un déploiement.",
        "how": "La toolbox inspecte les modes de fichiers, le PATH et les noms de variables sensibles.",
        "gain": "Des corrections fondées sur le moindre privilège sans révéler les valeurs des secrets.",
    },
    "crypto": {
        "title": "ENCODAGE, HACHAGE ET CHIFFREMENT",
        "why": "Éviter de confondre une représentation Base64, une empreinte et une protection par clé.",
        "when": "Lors de la conception d'un stockage, d'un échange ou d'un contrôle d'intégrité.",
        "how": "Le lab compare Base64, hash et XOR réversible exclusivement pédagogique.",
        "gain": "Le bon choix de mécanisme selon le besoin de confidentialité ou d'intégrité.",
    },
    "scripts": {
        "title": "ANALYSE STATIQUE DE SCRIPTS",
        "why": "Repérer rapidement les constructions sensibles avant d'exécuter ou de déployer un script.",
        "when": "En revue de code, analyse d'un artefact ou contrôle avant intégration.",
        "how": "Le fichier est lu sans exécution et comparé à des règles comme eval, shell=True ou pickle.",
        "gain": "Une liste de points à examiner manuellement avec leur ligne et leur impact possible.",
    },
}


def format_guide(name: str) -> str:
    guide = GUIDES[name]
    return (
        f"\n[{guide['title']}]\n"
        f"Pourquoi : {guide['why']}\n"
        f"Quand    : {guide['when']}\n"
        f"Comment  : {guide['how']}\n"
        f"Apport   : {guide['gain']}\n"
    )


def full_manual() -> str:
    intro = (
        "PARCOURS CONSEILLE\n"
        "1. Définir le périmètre et obtenir une autorisation.\n"
        "2. Découvrir les hôtes actifs.\n"
        "3. Scanner les ports des hôtes pertinents.\n"
        "4. Étudier en laboratoire les mots de passe et payloads.\n"
        "5. Analyser les journaux et le serveur HTTP du lab local.\n"
        "6. Consulter, fusionner et exporter les rapports.\n"
    )
    return intro + "\n" + "\n".join(format_guide(name) for name in GUIDES)
