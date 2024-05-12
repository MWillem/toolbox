#!/usr/bin/python3

def afficher_manuel():
    """Affiche le manuel d'utilisation de chaque outil."""
    manuel = """

    1. Scan de ports :
        - But : Scanner les ports ouverts sur une adresse IP spécifiée.
        - Utilisation : Entrez une adresse IP pour lancer le scan.

    2. BruteForce :
        - But : Effectuer une attaque de BruteForce sur un service spécifié.
        - Utilisation : Entrez une adresse IP, le numéro de port ou le service à cibler, et les chemins vers les fichiers de noms d'utilisateur et de mots de passe.

    3. Injecteur de payloads : 
        - But : automatisation d'injection de payloads
        - Utilisation : Backdoor : encours de développement

    4. Rapports :
        - But : Accéder aux rapports précédemment générés.
        - Utilisation : Choisissez cette option pour afficher la liste des rapports disponibles.

    5. Manuel d'utilisation :
        - But : Afficher ce manuel d'utilisation.

    6. Quitter :
        - But : Quitter l'application.
    """
    print(manuel)

if __name__ == "__main__":
    afficher_manuel()
