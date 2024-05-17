import subprocess
import ipaddress
import os

def valider_ip(ip_address):
    """Valide l'adresse IP."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        print("Adresse IP invalide.")
        return False

def executer_scan_ports(ip_address):
    """Exécute un scan de ports avec nmap."""
    command = ["nmap", "-sV", "-Pn", ip_address]
    output_lines = []
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                output_lines.append(output.strip())
        error = process.stderr.read()
        if error:
            print("Erreur lors du scan:", error)
    except Exception as e:
        print(f"Erreur lors de l'exécution de NMAP: {e}")
    return output_lines

def sauvegarder_resultats(ip_address, nom_fichier, results, chemin_rapports):
    """Sauvegarde les résultats du scan de ports."""
    chemin_complet = os.path.join(chemin_rapports, nom_fichier)
    try:
        with open(chemin_complet, "w") as fichier:
            fichier.write("\n\n****************************************************************\n")
            fichier.write(f"SCAN DE PORTS - {ip_address}\n")
            fichier.write("****************************************************************\n")
            fichier.write("\n".join(results))
        print(f"Résultats sauvegardés dans {chemin_complet}")
    except IOError as e:
        print(f"Erreur lors de l'enregistrement des résultats dans le fichier : {e}")

def main(chemin_rapports):
    """Fonction principale pour le scan de ports."""
    print("""
 _______ _______ _______ __   _      ______  _______       _____   _____   ______ _______                                                           
 |______ |       |_____| | \  |      |     \ |______      |_____] |     | |_____/    |                                                              
 ______| |_____  |     | |  \_|      |_____/ |______      |       |_____| |    \_    |    
 """)
    ip_address = input("Entrez l'adresse IP à scanner : ")
    if not valider_ip(ip_address):
        return
    nom_fichier = input("Entrez le nom du fichier pour sauvegarder les résultats : ")
    results = executer_scan_ports(ip_address)
    if results:
        sauvegarder_resultats(ip_address, nom_fichier, results, chemin_rapports)
    else:
        print("Aucun résultat à sauvegarder.")

if __name__ == "__main__":
    chemin_rapports = os.path.join(os.path.dirname(__file__), 'rapports')
    main(chemin_rapports)
