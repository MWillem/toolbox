import os

def afficher_rapports(chemin_vers_dossier_rapports):
    """
    Affiche les rapports disponibles dans un dossier spécifié et permet des interactions supplémentaires.
    """
    if not os.path.exists(chemin_vers_dossier_rapports):
        print("Aucun rapport n'est disponible.")
        return

    fichiers_rapports = os.listdir(chemin_vers_dossier_rapports)
    if not fichiers_rapports:
        print("Le dossier est vide.")
        return

    print("Liste des rapports disponibles :")
    for fichier in fichiers_rapports:
        print(fichier)

    choix_rapport = input("Entrez le nom du rapport à afficher, ou 'supprimer' pour supprimer un fichier, 'fusionner' pour fusionner des fichiers, 'quitter' pour sortir : ")

    if choix_rapport.lower() == 'supprimer':
        supprimer_rapport(chemin_vers_dossier_rapports)
    elif choix_rapport.lower() == 'fusionner':
        fusionner_rapports(chemin_vers_dossier_rapports)
    elif choix_rapport.lower() == 'quitter':
        return
    elif choix_rapport:
        afficher_contenu_rapport(chemin_vers_dossier_rapports, choix_rapport)

def afficher_contenu_rapport(chemin_vers_dossier_rapports, nom_rapport):
    chemin_rapport = os.path.join(chemin_vers_dossier_rapports, nom_rapport)
    if os.path.exists(chemin_rapport):
        try:
            with open(chemin_rapport, "r") as fichier:
                print(fichier.read())
        except Exception as e:
            print(f"Erreur lors de l'ouverture du fichier de rapport : {e}")
    else:
        print("Le rapport spécifié n'existe pas.")

def supprimer_rapport(chemin_vers_dossier_rapports):
    rapport_a_supprimer = input("Entrez le nom du rapport à supprimer : ")
    chemin_rapport = os.path.join(chemin_vers_dossier_rapports, rapport_a_supprimer)
    if os.path.exists(chemin_rapport):
        os.remove(chemin_rapport)
        print(f"Rapport {rapport_a_supprimer} supprimé.")
    else:
        print("Le rapport spécifié n'existe pas.")

def fusionner_rapports(chemin_vers_dossier_rapports):
    fichiers_a_fusionner = input("Entrez les noms des rapports à fusionner, séparés par une virgule : ").split(',')
    nom_fichier_final = input("Entrez le nom du fichier final : ")
    chemin_final = os.path.join(chemin_vers_dossier_rapports, nom_fichier_final)

    with open(chemin_final, 'w') as fichier_final:
        for nom_fichier in fichiers_a_fusionner:
            chemin_fichier = os.path.join(chemin_vers_dossier_rapports, nom_fichier.strip())
            if os.path.exists(chemin_fichier):
                with open(chemin_fichier, 'r') as fichier:
                    fichier_final.write(fichier.read() + "\n")
        print(f"Fichiers fusionnés en {nom_fichier_final}.")

if __name__ == "__main__":
    chemin_rapports = "/home/kali/Documents/toolbox/rapports/"
   
