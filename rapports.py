import os
import datetime

def list_backdoors(chemin_vers_dossier_rapports):
    fichiers_rapports = os.listdir(chemin_vers_dossier_rapports)
    fichiers_rapports.sort()
    if not fichiers_rapports:
        print("Aucun rapport disponible.")
        return None
    print("Liste des rapports disponibles :")
    for idx, fichier in enumerate(fichiers_rapports, start=1):
        print(f"{idx}. {fichier}")
    return fichiers_rapports

def choisir_rapport(fichiers_rapports):
    if fichiers_rapports:
        choix = int(input("Choisissez un rapport par numéro, ou 0 pour quitter : "))
        if choix == 0:
            return None
        return fichiers_rapports[choix - 1]
    return None

def afficher_rapport(chemin_rapport):
    if os.path.exists(chemin_rapport):
        with open(chemin_rapport, "r") as fichier:
            print(f"\nContenu de {os.path.basename(chemin_rapport)}:")
            print(fichier.read())
    else:
        print("Le fichier spécifié n'existe pas.")

def supprimer_rapport(chemin_rapport):
    if os.path.exists(chemin_rapport):
        os.remove(chemin_rapport)
        print(f"Le rapport {os.path.basename(chemin_rapport)} a été supprimé.")
    else:
        print("Le rapport spécifié n'existe pas.")

def fusionner_rapports(chemin_vers_dossier_rapports, fichiers_rapports):
    print("Sélectionnez les rapports à fusionner par numéro, séparés par une virgule (ex: 1,3,5):")
    indices = input().split(',')
    nom_fichier_final = input("Entrez le nom du fichier final : ")
    chemin_final = os.path.join(chemin_vers_dossier_rapports, nom_fichier_final)

    with open(chemin_final, 'w') as fichier_final:
        for index in indices:
            chemin_fichier = os.path.join(chemin_vers_dossier_rapports, fichiers_rapports[int(index) - 1])
            with open(chemin_fichier, 'r') as fichier:
                fichier_final.write(fichier.read() + "\n")
        print(f"Fichiers fusionnés en {nom_fichier_final}.")

def gestion_rapports(chemin_rapports):
    print("""
  ______ _______  _____   _____   _____   ______ _______ _______
 |_____/ |_____| |_____] |_____] |     | |_____/    |    |______
 |    \_ |     | |       |       |_____| |    \_    |    ______|
 """)
    while True:
        fichiers_rapports = list_backdoors(chemin_rapports)
        if not fichiers_rapports:
            break
        rapport_choisi = choisir_rapport(fichiers_rapports)
        if not rapport_choisi:
            break
        action = input("Choisissez une action - Afficher (a), Supprimer (s), Fusionner (f), Quitter (q): ")
        chemin_rapport = os.path.join(chemin_rapports, rapport_choisi)
        if action.lower() == 'a':
            afficher_rapport(chemin_rapport)
        elif action.lower() == 's':
            supprimer_rapport(chemin_rapport)
        elif action.lower() == 'f':
            fusionner_rapports(chemin_rapports, fichiers_rapports)
        elif action.lower() == 'q':
            break

if __name__ == "__main__":
    gestion_rapports()
