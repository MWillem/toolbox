import os

def afficher_rapports():
    # Chemin vers le dossier contenant les rapports
    chemin_vers_dossier_rapports = "chemin_vers_dossier_rapports"

    # Vérifier si le dossier des rapports existe
    if not os.path.exists(chemin_vers_dossier_rapports):
        print("Aucun rapport n'est disponible.")
        return

    # Récupérer la liste des fichiers de rapports
    fichiers_rapports = os.listdir(chemin_vers_dossier_rapports)

    # Afficher la liste des rapports
    print("Liste des rapports disponibles :")
    for fichier in fichiers_rapports:
        print(fichier)

    # Demander à l'utilisateur de choisir un rapport à afficher
    choix_rapport = input("Entrez le nom du rapport à afficher (ou appuyez sur Entrée pour revenir au menu principal) : ")

    # Vérifier si l'utilisateur a fait un choix
    if choix_rapport:
        chemin_rapport = os.path.join(chemin_vers_dossier_rapports, choix_rapport)
        
        # Vérifier si le rapport spécifié existe
        if os.path.exists(chemin_rapport):
            # Afficher le contenu du rapport
            with open(chemin_rapport, "r") as f:
                contenu_rapport = f.read()
                print(contenu_rapport)
        else:
            print("Le rapport spécifié n'existe pas.")
