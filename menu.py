import os
import sys

# Chemin vers le dossier 'tools'
chemin_tools = os.path.abspath(os.path.join(os.path.dirname(__file__), 'tools'))
sys.path.append(chemin_tools)

# Chemin vers le dossier 'payloads' dans 'tools'
chemin_payloads = os.path.abspath(os.path.join(chemin_tools, 'payloads'))
sys.path.append(chemin_payloads)

# Importer les fonctions nécessaires depuis chaque fichier
from scan_port import scan_ports, scan_ports_generer_json
from bruteforce import bruteforce
from rapports import afficher_rapports
from payload_injector import payload_injector  
from man import afficher_manuel

def main():

    while True:
        os.system('clear')  # clear the screen
        print("""
  ____            _            _     _              _  
 |  _ \ ___ _ __ | |_ ___  ___| |_  | |_ ___   ___ | |
 | |_) / _ \ '_ \| __/ _ \/ __| __| | __/ _ \ / _ \| | 
 |  __/  __/ | | | ||  __/\__ \ |_  | || (_) | (_) | | 
 |_|   \___|_| |_|\__\___||___/\__|  \__\___/ \___/|_|
 """)
        print("Bienvenue dans la Toolbox de Pentest")
        print("1. Scan de ports")
        print("2. BruteForce")
        print("3. Injecteur de Payload")
        print("4. Gestion des rapports")
        print("5. Quitter")
        choix = input("Entrez votre choix : ")

        if choix == '1':
            ip_address = input("Entrez l'adresse IP à scanner : ")
            filename = input("Entrez le nom du fichier pour sauvegarder les résultats (ex: resultat_scan.json) : ")
            scan_ports_generer_json(ip_address, filename)
        elif choix == '2':
            bruteforce()
        elif choix == '3':
            payload_injector()
        elif choix == '4':
            chemin_rapports = "/home/kali/Documents/toolbox/rapports/"
            afficher_rapports(chemin_rapports)
        elif choix == '5':
            print("Merci d'utiliser la Toolbox de Pentest. À bientôt !")
            break
        else:
            print("Choix invalide. Veuillez réessayer.")
        
        input("Appuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()