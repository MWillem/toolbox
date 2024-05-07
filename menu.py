import os
import subprocess
import sys
import json

# Assurez-vous que le dossier tools est ajouté au chemin de recherche des modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fonctionnalites.bruteforce import bf_hydra_et_generer_json

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
            service = input("Entrez le numéro de port ou le service à rechercher (ex: 21 pour FTP, ssh pour SSH) : ")
            chemin_utilisateurs = input("Entrez le chemin de la bibliothèque des utilisateurs (laissez vide pour utiliser /usr/share/wordlists/rockyou2.txt) : ")
            if not chemin_utilisateurs:
                chemin_utilisateurs = "/usr/share/wordlists/rockyou2.txt"
            chemin_mots_de_passe = input("Entrez le chemin de la bibliothèque des mots de passe (laissez vide pour utiliser /usr/share/wordlists/rockyou2.txt) : ")
            if not chemin_mots_de_passe:
                chemin_mots_de_passe = "/usr/share/wordlists/rockyou2.txt"
            resultats_json = bf_hydra_et_generer_json(ip_address, service, chemin_utilisateurs, chemin_mots_de_passe)
            print("Résultats du BruteForce (format JSON) :")
            print(resultats_json)
        elif choix == '4':
            rapports()
        elif choix == '5':
            man()
        elif choix == '6':
            quitter()
        else:
            print("Choix invalide. Veuillez choisir un numéro entre 1 et 6.")

if __name__ == "__main__":
    main()
