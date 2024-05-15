import os
import sys

def configurer_chemins():
    chemin_base = os.path.dirname(__file__)
    chemin_tools = os.path.abspath(os.path.join(chemin_base, 'tools'))
    sys.path.append(chemin_tools)

    chemin_payloads = os.path.abspath(os.path.join(chemin_tools, 'payloads'))
    sys.path.append(chemin_payloads)

def clear_screen():
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Unix/Linux/Mac
        os.system('clear')

configurer_chemins()

from scan_port import main as scan_ports_main
from mapping_reseau import main as mapping_reseau_main
from bruteforce import main as bruteforce_main
from payload_injector import payload_injector
from rapports import gestion_rapports
from man import afficher_manuel 

def main():

    while True:
        clear_screen()  # Use the clear_screen function
        print("""                                        
  _____ ___   ___  _     ____   _____  __
 |_   _/ _ \ / _ \| |   | __ ) / _ \ \/ /
   | || | | | | | | |   |  _ \| | | \  / 
   | || |_| | |_| | |___| |_) | |_| /  \ 
   |_| \___/ \___/|_____|____/ \___/_/\_\ 
""")
        print("Bienvenue dans la Toolbox de Pentest")
        print("1. Maaping réseau")
        print("2. Scan de ports")
        print("3. BruteForce")
        print("4. Injecteur de Payload")
        print("5. Gestion des rapports")
        print("6. Manuel")
        print("7. Quitter")
        choix = input("Entrez votre choix : ")

        if choix == "1":
            mapping_reseau_main()
        elif choix == '2':
            scan_ports_main()
        elif choix == '3':
            bruteforce_main()
        elif choix == '4':
            payload_injector()
        elif choix == '5':
            chemin_rapports = "/home/kali/Documents/toolbox/rapports/"
            gestion_rapports(chemin_rapports)
        elif choix == '6':
            afficher_manuel()
        elif choix == '7':
            print("Merci d'utiliser la Toolbox de Pentest. À bientôt !")
            break
        else:
            print("Choix invalide. Veuillez réessayer.")
        
        input("Appuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()
