import nmap
import os
import ipaddress

def valider_ip_sous_reseau(ip_sous_reseau):
    """Valide l'adresse IP et le masque de sous-réseau."""
    try:
        ipaddress.ip_network(ip_sous_reseau, strict=False)
        return True
    except ValueError:
        print("L'adresse IP ou le masque de sous-réseau est invalide.")
        return False

def executer_mapping_reseau(ip_sous_reseau):
    """Exécute un scan de mappage réseau avec nmap et affiche les résultats en dynamique."""
    scanner = nmap.PortScanner()
    hôtes_actifs = []
    try:
        scanner.scan(hosts=ip_sous_reseau, arguments='-sn')
        for host in scanner.all_hosts():
            print(f"Hôte actif : {host}")
            hôtes_actifs.append(host)
        return hôtes_actifs
    except nmap.PortScannerError as e:
        print(f"Erreur lors du scan : {e}")
        return []

def sauvegarder_rapport(ip_sous_reseau, hôtes_actifs, chemin_rapports, nom_fichier):
    """Sauvegarde le rapport du mappage réseau."""
    chemin_complet = os.path.join(chemin_rapports, nom_fichier)
    os.makedirs(chemin_rapports, exist_ok=True)  # Crée le répertoire s'il n'existe pas
    try:
        with open(chemin_complet, "w") as fichier:
            fichier.write(f"Résultats du scan de réseau pour {ip_sous_reseau}\n\n")
            for host in hôtes_actifs:
                fichier.write(f"Hôte actif : {host}\n")
        print(f"Rapport sauvegardé dans {chemin_complet}")
    except IOError as e:
        print(f"Erreur lors de l'enregistrement du rapport : {e}")

def main(chemin_rapports):
    """Fonction principale pour le mappage réseau."""
    print("""
 _______ _______  _____   _____  _____ __   _  ______       ______ _______ _______ _______ _______ _     _                                          
 |  |  | |_____| |_____] |_____]   |   | \  | |  ____      |_____/ |______ |______ |______ |_____| |     |                                          
 |  |  | |     | |       |       __|__ |  \_| |_____|      |    \_ |______ ______| |______ |     | |_____|
 """)
    ip_sous_reseau = input("Entrez l'adresse IP avec le masque de sous-réseau (ex : 192.168.1.0/24) : ")
    if valider_ip_sous_reseau(ip_sous_reseau):
        hôtes_actifs = executer_mapping_reseau(ip_sous_reseau)
        if hôtes_actifs:
            nom_fichier = input("Entrez le nom du fichier pour sauvegarder le rapport : ")
            sauvegarder_rapport(ip_sous_reseau, hôtes_actifs, chemin_rapports, nom_fichier)
        else:
            print("Aucun hôte actif détecté.")
    else:
        print("Veuillez entrer une adresse IP avec un masque de sous-réseau valide.")

if __name__ == "__main__":
    chemin_rapports = os.path.join(os.path.dirname(__file__), 'rapports')
    main(chemin_rapports)
