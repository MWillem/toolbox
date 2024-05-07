import os
import subprocess
import sys
import json

# Assurez-vous que le dossier tools est ajouté au chemin de recherche des modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'tools')))

# Importer la fonction nécessaire depuis chaque fichier
from scan_reseau import scan_reseau, scan_reseau_et_generer_json
from scan_port import scan_ports, scan_ports_et_generer_json
from bruteforce import bf_hydra, generer_json
from rapports import afficher_rapports
from man import afficher_manuel as man_func


def main():
    print("""
  ____            _            _     _              _  
 |  _ \ ___ _ __ | |_ ___  ___| |_  | |_ ___   ___ | |
 | |_) / _ \ '_ \| __/ _ \/ __| __| | __/ _ \ / _ \| | 
 |  __/  __/ | | | ||  __/\__ \ |_  | || (_) | (_) | | 
 |_|   \___|_| |_|\__\___||___/\__|  \__\___/ \___/|_|
 """)

    while True:
        print("\nChoisissez une option :")
        print("1. Scan de réseau")
        print("2. Scan de ports")
        print("3. BruteForce")
        print("4. Rapports")
        print("5. Manuel d'utilisation")
        print("6. Quitter")

        choix = input("Entrez le numéro de votre choix : ")

        if choix == '1':
            adresse_ip = input("Entrez une adresse IP pour rechercher les adresses IP existantes autour d'elle : ")
            resultats_json = scan_reseau_et_generer_json(adresse_ip)
            print("Résultats du scan de réseau (format JSON) :")
            print(resultats_json)
        elif choix == '2':
            ip_address = input("Entrez une adresse IP à scanner : ")
            resultats_json = scan_ports_et_generer_json(ip_address)
            print("Résultats du scan de ports (format JSON) :")
            print(resultats_json)
        elif choix == '3':
            ip_address = input("Entrez une adresse IP à scanner : ")
            port = input("Entrez le numéro de port : ")
            service = input("Entrez le service : ")
            chemin_utilisateurs = input("Entrez le chemin des utilisateurs : ")
            chemin_mots_de_passe = input("Entrez le chemin des mots de passe : ")
            
            credentials = bf_hydra(ip_address, port, service, chemin_utilisateurs, chemin_mots_de_passe)
            
            if credentials:
                nom_fichier = input("Entrez le nom du fichier JSON : ")
                generer_json(credentials, nom_fichier)
        if choix == '4':
            afficher_rapports()
        elif choix == '5':
            man_func()
        elif choix == '6':
            print("Merci d'avoir utilisé l'outil. Au revoir !")
            break

        else:
            print("Choix invalide. Veuillez choisir un numéro entre 1 et 6.")

if __name__ == "__main__":
    main()
