import subprocess
import ipaddress
import os

def valider_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        print("Adresse IP invalide.")
        return False

def executer_scan_ports(ip_address):
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

def sauvegarder_resultats(ip_address, nom_fichier, results):
    chemin_complet = os.path.join("/home/kali/Documents/toolbox/rapports/", nom_fichier)
    try:
        with open(chemin_complet, "w") as fichier:
            f.write("\n\n****************************************************************\n")
            f.write(f"SCAN DE PORTS - - {ip_address}\n")
            f.write("****************************************************************\n")
            fichier.write("\n".join(results))
        print(f"Résultats sauvegardés dans {chemin_complet}")
    except IOError as e:
        print(f"Erreur lors de l'enregistrement des résultats dans le fichier : {e}")

def main():
    print("""
 _______ _______ _______ __   _      ______  _______       _____   _____   ______ _______                                                           
 |______ |       |_____| | \  |      |     \ |______      |_____] |     | |_____/    |                                                              
 ______| |_____  |     | |  \_|      |_____/ |______      |       |_____| |    \_    |    
 """)
    ip_address = input("Entrez l'adresse IP à scanner : ")
    if not valider_ip(ip_address):
        return
    nom_fichier = input("Entrez le nom du fichier pour sauvegarder les résultats (ex: resultat_scan.json) : ")
    results = executer_scan_ports(ip_address)
    if results:
        sauvegarder_resultats(ip_address, nom_fichier, results)
    else:
        print("Aucun résultat à sauvegarder.")

if __name__ == "__main__":
    main()
