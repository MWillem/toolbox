from backdoor import reverse_shell

def payload_injector(chemin_rapports):
    """Affiche le menu pour l'injection de payloads."""
    print(r"""
  ___ _   _     _ _____ ____ _____ ___ ___  _   _       _        ____   _ __   ___     ___    _    ____  
 |_ _| \ | |   | | ____/ ___|_   _|_ _/ _ \| \ | |   __| | ___  |  _ \ / \\ \ / / |   / _ \  / \  |  _ \ 
  | ||  \| |_  | |  _|| |     | |  | | | | |  \| |  / _` |/ _ \ | |_) / _ \\ V /| |  | | | |/ _ \ | | | |
  | || |\  | |_| | |__| |___  | |  | | |_| | |\  | | (_| |  __/ |  __/ ___ \| | | |__| |_| / ___ \| |_| |
 |___|_| \_|\___/|_____\____| |_| |___\___/|_| \_|  \__,_|\___| |_| /_/   \_\_| |_____\___/_/   \_\____/ 
 """)
    while True:
        print("\nMenu Injecteur de Payload")
        print("1. Injecter une backdoor")
        print("2. Autres payloads (à développer)")
        print("3. Retourner au menu principal")
        choix_payload = input("Entrez votre choix : ")

        if choix_payload == '1':
            try:
                reverse_shell(chemin_rapports)
                print("Payload injecté avec succès.")
            except Exception as e:
                print(f"Erreur lors de l'injection du payload : {e}")
        elif choix_payload == '2':
            print("Autres types de payloads seront bientôt disponibles...")
        elif choix_payload == '3':
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

        input("Appuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    chemin_rapports = os.path.join(os.path.dirname(__file__), 'rapports')
    payload_injector(chemin_rapports)
