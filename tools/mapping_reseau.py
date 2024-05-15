import nmap
import os
import ipaddress

def valider_ip_sous_reseau(ip_sous_reseau):
    try:
        ipaddress.ip_network(ip_sous_reseau, strict=False)
        return True
    except ValueError:
        print("L'adresse IP ou le masque de sous-réseau est invalide.")
        return False

def executer_mapping_reseau(ip_sous_reseau):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=ip_sous_reseau, arguments='-sn')
        return scanner.all_hosts()
    except nmap.nmap.PortScannerError as e:
        print(f"Erreur lors du scan : {e}")
        return []

def sauvegarder_rapport(ip_sous_reseau, hôtes_actifs):
    nom_fichier = f"rapport_mapping_{ip_sous_reseau.replace('/', '_')}.txt"
    chemin_complet = os.path.join("/home/kali/Documents/toolbox/rapports/", nom_fichier)
    try:
        with open(chemin_complet, "w") as fichier:
            fichier.write(f"Résultats du scan de réseau pour {ip_sous_reseau}\n\n")
            for host in hôtes_actifs:
                fichier.write(f"Hôte actif : {host}\n")
        print(f"Rapport sauvegardé dans {chemin_complet}")
    except IOError as e:
        print(f"Erreur lors de l'enregistrement du rapport : {e}")

def main():
    print("""
 _______ _______  _____   _____  _____ __   _  ______       ______ _______ _______ _______ _______ _     _                                          
 |  |  | |_____| |_____] |_____]   |   | \  | |  ____      |_____/ |______ |______ |______ |_____| |     |                                          
 |  |  | |     | |       |       __|__ |  \_| |_____|      |    \_ |______ ______| |______ |     | |_____|
 """)
    ip_sous_reseau = input("Entrez l'adresse IP avec le masque de sous-réseau (ex : 192.168.1.0/24) : ")
    if valider_ip_sous_reseau(ip_sous_reseau):
        hôtes_actifs = executer_mapping_reseau(ip_sous_reseau)
        if hôtes_actifs:
            sauvegarder_rapport(ip_sous_reseau, hôtes_actifs)
        else:
            print("Aucun hôte actif détecté.")
    else:
        print("Veuillez entrer une adresse IP avec un masque de sous-réseau valide.")

if __name__ == "__main__":
    main()
