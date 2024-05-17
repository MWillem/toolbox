markdown

# Toolbox de Pentest
    Bienvenue dans la Toolbox de Pentest, une suite d'outils automatisés pour réaliser des tests de pénétration. Cette toolbox        inclut des fonctionnalités pour le mapping réseau, le scan de ports, le brute force, l'injection de payloads, et la gestion       des rapports.

## Structure de la Toolbox

    toolbox/
    ├── menu.py
    ├── rapports.py
    ├── requirements.txt
    ├── tools/
    │   ├── bruteforce.py
    │   ├── mapping_reseau.py
    │   ├── payloads/
    │   │   ├── backdoor.py
    │   │   ├── payload_injector.py
    │   │   └── bibli_backdoor/
    │   └── scan_port.py
    └── rapports/

## Prérequis
Avant d'utiliser la toolbox, assurez-vous que les dépendances nécessaires sont installées.
### Linux (Kali ou parrotOS de préférence)
Python 3
nmap
hydra

## Installation :
Clonez le dépôt GitHub sur votre machine locale :

    git clone https://github.com/MWillem/toolbox.git
    cd toolbox

## Installer les dépendances :

    sudo apt update
    sudo apt install python3 python3-pip nmap hydra
    pip3 install -r requirements.txt

## Utilisation :
Pour lancer la toolbox, exécutez le script menu.py.

    python3 menu.py

## Fonctionnalités :
Mapping réseau : Effectue un mapping réseau en utilisant Nmap.
Scan de ports : Scanne les ports ouverts sur une adresse IP spécifiée.
BruteForce : Lance une attaque par force brute sur un service spécifié.
Injecteur de Payload : Injecte des payloads (backdoors) sur une cible spécifiée.
Gestion des rapports : Affiche, supprime et fusionne les rapports générés par les autres outils.

## Dépannage :
Si vous rencontrez des problèmes, veuillez vérifier que toutes les dépendances sont correctement installées et que vous           utilisez les versions compatibles des outils et des bibliothèques.

