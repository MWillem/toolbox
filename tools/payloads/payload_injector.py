def payload_injector():
    while True:
        print("Menu Injecteur de Payload")
        print("1. Injecter une backdoor")
        print("2. Autres payloads (à développer)")
        print("3. Retourner au menu principal")
        choix_payload = input("Entrez votre choix : ")

        if choix_payload == '1':
            # Nous devons nous assurer que la fonction pour injecter la backdoor est importée.
            # from backdoor import main as inject_backdoor
            inject_backdoor()
        elif choix_payload == '2':
            print("Autres types de payloads seront bientôt disponibles...")
        elif choix_payload == '3':
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

        input("Appuyez sur Entrée pour continuer...")