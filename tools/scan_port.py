import subprocess
import ipaddress
import os

def scan_ports(ip_address):
    """
    Utilise NMAP pour scanner les ports ouverts d'une adresse IP donnée, affiche les résultats en direct
    et sauvegarde la sortie dans un fichier texte.
    """
    try:
        # Valide l'adresse IP
        ipaddress.ip_address(ip_address)
    except ValueError:
        print("Adresse IP invalide.")
        return

    command = ["nmap", "-sV", "-Pn", ip_address]
    output_lines = []  # Liste pour stocker la sortie de NMAP

    try:
        # Démarrage du processus NMAP
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Lecture et affichage des résultats en temps réel
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                output_lines.append(output.strip())

        # Vérifie s'il y a des erreurs
        error = process.stderr.read()
        if error:
            print("Erreur lors du scan:", error)

    except Exception as e:
        print(f"Erreur lors de l'exécution de NMAP: {e}")

    return output_lines

def scan_ports_generer_json(ip_address, nom_fichier):
    """
    Exécute le scan des ports et sauvegarde les résultats dans un fichier spécifié dans le dossier des rapports.
    L'en-tête du fichier contiendra "SCAN DE PORTS - (avec adresses IP cibles)".
    """
    results = scan_ports(ip_address)
    if not results:
        print("Aucun résultat de scan de ports disponible.")
        return

    chemin_complet = os.path.join("/home/kali/Documents/toolbox/rapports/", nom_fichier)
    try:
        with open(chemin_complet, "w") as fichier:
            # Écrire l'en-tête avec l'adresse IP cible
            fichier.write(f"***************************************\nSCAN DE PORTS - {ip_address}\n***************************************\n\n")
            fichier.write("\n".join(results))
        print(f"Résultats sauvegardés dans {chemin_complet}")
    except IOError as e:
        print(f"Erreur lors de l'enregistrement des résultats dans le fichier : {e}")