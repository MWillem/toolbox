#!/usr/bin/python3

def afficher_manuel():
    """Affiche le manuel d'utilisation de chaque outil."""
    print(r"""
 _______ _______ __   _ _     _ _______                         
 |  |  | |_____| | \  | |     | |______ |                       
 |  |  | |     | |  \_| |_____| |______ |_____
    """)
    manuel = """
    Conditions d'utilisation :
        Cet outil est conçu uniquement pour les tests de pénétration légaux et éthiques.
        Toute utilisation à des fins illégales est strictement interdite et peut entraîner
        des poursuites pénales. En utilisant cet outil, vous acceptez d'être responsable
        de vos actions et de respecter toutes les lois et réglementations applicables.

    Description de la Toolbox :
        La toolbox permet un suivi logique d'un test d'intrusion qui commence par un mappage réseau, 
        continue avec un scan de ports pour trouver les services vulnérables, puis effectue une attaque
        par force brute sur les services vulnérables pour récupérer les identifiants et enfin initie
        une connexion sur ce service pour y déposer une backdoor. La génération de rapports est intégrée
        pour permettre de retracer le parcours du pentest avec les informations récupérées et les processus
        réussis ou non.

    1. Mappage réseau :
        - But : Scanner les hôtes actifs sur un réseau spécifié.
        - Utilisation : Entrez l'adresse IP avec le masque de sous-réseau (ex : 192.168.1.0/24).

    2. Scan de ports :
        - But : Scanner les ports ouverts sur une adresse IP spécifiée.
        - Utilisation : Entrez une adresse IP pour lancer le scan.

    3. BruteForce :
        - But : Effectuer une attaque par force brute sur un service spécifié.
        - Utilisation : Entrez une adresse IP, le numéro de port ou le service à cibler, 
          et les chemins vers les fichiers de noms d'utilisateur et de mots de passe.

    4. Injecteur de payloads : 
        - But : Automatiser l'injection de payloads.
        - Utilisation : Choisissez l'option "Injecter une backdoor" et suivez les instructions.
            Backdoor : 
                - But : Avoir un reverse shell sur l'outil
                - Utilisation : Choix du service (pour l'instant ftp ou ssh), entrée des crédentials,
                entrée du port à mettre en écoute, choix du script de la backdoor à déposer dans la liste
                - déroulement : Une fois le script déposé l'outil reste en écoute sur le port choisis. si la backdoor
                s'activent le reverse shell apparaît. (Cette étape dépend du script que vous avez mis en place dans la biliothèque de backdoor,
                celui disponible par défaut est facilement repérable par le pare-feu windows et ne se lance pas automatiquement)

    5. Gestion des rapports :
        - But : Accéder aux rapports générés précédemment.
        - Utilisation : Choisissez cette option pour afficher, supprimer ou fusionner les rapports disponibles.

    6. Manuel d'utilisation :
        - But : Afficher ce manuel d'utilisation.

    7. Quitter :
        - But : Quitter l'application.
    """
    print(manuel)

if __name__ == "__main__":
    afficher_manuel()
