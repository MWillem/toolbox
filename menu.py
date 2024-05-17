import os
import sys

def configurer_chemins():
    """Configure les chemins des répertoires tools et payloads."""
    chemin_base = os.path.dirname(__file__)
    chemin_tools = os.path.abspath(os.path.join(chemin_base, 'tools'))
    sys.path.append(chemin_tools)

    chemin_payloads = os.path.abspath(os.path.join(chemin_tools, 'payloads'))
    sys.path.append(chemin_payloads)

def clear_screen():
    """Efface l'écran."""
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Unix/Linux/Mac
        os.system('clear')

def afficher_conditions_utilisation():
    """Affiche les conditions d'utilisation et demande l'accord de l'utilisateur."""
    conditions = """
    ************************** CONDITIONS D'UTILISATION **************************

    Cet outil est conçu uniquement pour les tests de pénétration légaux et éthiques.
    Toute utilisation à des fins illégales est strictement interdite et peut entraîner
    des poursuites pénales. En utilisant cet outil, vous acceptez d'être responsable
    de vos actions et de respecter toutes les lois et réglementations applicables.

    Acceptez-vous ces conditions ? (o/n) : 
    ******************************************************************************
    """
    print(conditions)
    choix = input().strip().lower()
    return choix == 'o'

configurer_chemins()

from scan_port import main as scan_ports_main
from mapping_reseau import main as mapping_reseau_main
from bruteforce import main as bruteforce_main
from payload_injector import payload_injector
from rapports import gestion_rapports
from man import afficher_manuel 

def main():
    """Fonction principale pour afficher le menu et gérer les choix de l'utilisateur."""
    if not afficher_conditions_utilisation():
        print("Vous devez accepter les conditions d'utilisation pour utiliser cet outil.")
        return

    chemin_rapports = os.path.join(os.path.dirname(__file__), 'rapports')
    
    if not os.path.exists(chemin_rapports):
        os.makedirs(chemin_rapports)

    while True:
        clear_screen()  # Utilise la fonction clear_screen pour effacer l'écran
        print("""                                        
  _____ ___   ___  _     ____   _____  __
 |_   _/ _ \ / _ \| |   | __ ) / _ \ \/ /
   | || | | | | | | |   |  _ \| | | \  / 
   | || |_| | |_| | |___| |_) | |_| /  \ 
   |_| \___/ \___/|_____|____/ \___/_/\_\ 
""")
        print("Bienvenue dans la Toolbox de Pentest")
        print("1. Mappage réseau")
        print("2. Scan de ports")
        print("3. BruteForce")
        print("4. Injecteur de Payload")
        print("5. Gestion des rapports")
        print("6. Manuel")
        print("7. Quitter")
        choix = input("Entrez votre choix : ")

        if choix == "1":
            mapping_reseau_main(chemin_rapports)
        elif choix == '2':
            scan_ports_main(chemin_rapports)
        elif choix == '3':
            bruteforce_main(chemin_rapports)
        elif choix == '4':
            payload_injector(chemin_rapports)
        elif choix == '5':
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
