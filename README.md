# Cyber Learning Toolbox

Une toolbox pédagogique issue d'un projet de Master. Elle reproduit le fil
logique d'un audit de cybersécurité tout en expliquant chaque étape :

1. conduire une mission guidée de la définition du périmètre au rapport ;
2. découvrir les machines actives d'un réseau privé ;
3. scanner leurs ports et identifier les services avec Nmap ;
4. comprendre les attaques par dictionnaire dans un lab local ;
5. analyser des journaux suspects et un payload factice ;
6. auditer un serveur HTTP local volontairement incomplet ;
7. consulter, fusionner et exporter les rapports depuis l'application.

L'objectif n'est pas seulement d'exécuter une commande. Chaque atelier précise
**pourquoi** il existe, **quand** l'utiliser, **comment** il fonctionne et
**ce que son résultat apporte**.

## Menu principal

```text
  _____ ___   ___  _     ____   _____  __
 |_   _/ _ \ / _ \| |   | __ ) / _ \ \/ /
   | || | | | | | | |   |  _ \| | | \  /
   | || |_| | |_| | |___| |_) | |_| /  \
   |_| \___/ \___/|_____|____/ \___/_/\_\

1. Mode Watchdog - opération scénarisée
2. Mission guidée complète
3. Mappage réseau - hôtes actifs
4. Scan de ports - Nmap
5. Laboratoire local
6. Lab mots de passe
7. Gestion des rapports
8. Manuel et parcours guidé
9. Outils complémentaires
10. Paramètres
11. Vue globale des capacités
12. Interface graphique responsive
```

## Interface graphique

Le menu principal propose une interface web locale responsive inspirée des
consoles de surveillance technologique. Elle utilise une identité originale :
aucun logo, nom ou élément graphique du jeu Watch Dogs n'est intégré.

Sous Windows :

```powershell
.\run.bat gui
# ou
.\gui.bat
```

Sous Linux, macOS ou Termux :

```bash
sh run.sh gui
# ou
sh gui.sh
```

La page `http://127.0.0.1:8765` s'ouvre dans le navigateur. Elle contient le
tableau de bord, le profil technique d'un appareil autorisé, l'audit HTTP, le
laboratoire local, les rapports et les paramètres. Les conditions d'utilisation
doivent être acceptées avant d'accéder aux modules.

Sur Termux, si le navigateur ne s'ouvre pas automatiquement :

```bash
sh run.sh gui --no-browser
```

Puis ouvrez `http://127.0.0.1:8765` dans le navigateur Android.

Pour consulter depuis un téléphone l'interface lancée sur un PC du même réseau :

```powershell
.\run.bat gui --lan --no-browser
```

L'option `--lan` expose volontairement la console sur le réseau local. Elle
doit uniquement être utilisée sur un réseau de confiance, puis arrêtée avec
`Ctrl+C` après la démonstration. Sans cette option, le serveur écoute uniquement
sur l'appareil qui l'a lancé.

## Fonctionnalités

### Mode Watchdog

Le menu propose une opération scénarisée séparée du mode professionnel :

```powershell
.\run.bat watchdog
```

L'opération **Signal Fantôme** génère uniquement des artefacts locaux, puis
demande de :

1. corréler des échecs de connexion avec une authentification réussie ;
2. reconnaître les comportements d'un payload texte factice ;
3. identifier le risque provoqué par `shell=True` dans un script.

Des indices sont proposés en cas d'erreur. Le rapport final repose toujours sur
les analyseurs techniques de la toolbox, afin que la narration ne remplace pas
les preuves. Ce mode n'analyse aucune machine tierce et n'exécute aucun artefact.

Le même menu propose aussi le profil technique d'un appareil réel autorisé :

```powershell
.\run.bat profile 192.168.1.25 --ports 1-1024 --authorized
```

La fiche peut contenir :

- adresse IP et nom réseau ;
- adresse MAC lorsqu'elle est visible sur le même segment local ;
- fabricant lorsque Nmap peut l'associer à sa base OUI locale ;
- type probable : PC, serveur, téléphone, imprimante, routeur, caméra, TV ou
  appareil réseau générique ;
- ports, services, produits et versions observés ;
- indices utilisés, niveau de confiance et limites.

Le type reste une estimation technique. Une MAC randomisée, un pare-feu ou des
services masqués peuvent réduire fortement la précision. La fiche ne cherche
jamais à identifier la personne qui utilise l'appareil.

Lorsque la corrélation réseau/Internet est activée dans les paramètres, un nom
d'appareil peut aussi être résolu en DNS. Pour un domaine public explicitement
fourni, un profil passif regroupe DNS, TLS et en-têtes HTTPS :

```powershell
.\run.bat asset example.org
```

Ce profil ne scanne pas les ports publics et n'effectue aucune attribution
personnelle. Les CDN, VPN, proxys et hébergements partagés limitent fortement
les conclusions possibles.

### Mission guidée

Le mode Mission relie les outils dans l'ordre d'un audit :

1. saisie du périmètre privé et de la référence d'autorisation ;
2. découverte des hôtes ;
3. sélection d'une cible ;
4. scan de ses ports ;
5. recommandations adaptées aux services observés ;
6. sauvegarde de la session et génération d'un rapport professionnel.

Il évite de perdre le contexte entre deux commandes et montre comment passer
d'une observation technique à une recommandation.

### Mappage réseau

La toolbox utilise `nmap -sn` pour rechercher les hôtes actifs sur un réseau
privé limité à 256 adresses. Si Nmap n'est pas installé, elle utilise le
programme `ping` comme mode de secours.

### Scan de ports

Lorsque Nmap est disponible, `nmap -sV` identifie les ports ouverts, les
services, produits et versions. Le repli portable utilise des connexions TCP
Python, avec moins d'informations.

### Lab mots de passe

Deux exercices sont proposés :

- évaluer la robustesse et l'entropie théorique d'un mot de passe ;
- créer localement son hash SHA-256 puis tenter de le retrouver avec une liste
  de candidats bornée à 100 000 entrées.

Le lab n'attaque aucun service distant et n'enregistre jamais le mot de passe
retrouvé dans les rapports. Une liste de démonstration est fournie dans
`labs/wordlists/demo.txt`.

### Lab payloads

La toolbox peut :

- calculer la taille et l'empreinte SHA-256 d'un fichier ;
- relever quelques indicateurs simples comme PowerShell, Netcat ou `curl` ;
- créer et déposer un fichier texte totalement inoffensif pour expliquer le
  transport d'un artefact sans l'exécuter.

Elle ne déploie pas de backdoor et n'ouvre pas de reverse shell.

### Laboratoire local

La commande suivante prépare le laboratoire :

```powershell
.\run.bat lab-prepare
```

Elle crée :

- un journal SSH/web contenant des échecs répétés, une connexion réussie et des
  requêtes sensibles ;
- un payload texte factice contenant des indicateurs à identifier ;
- un script volontairement risqué à analyser sans l'exécuter ;
- un artefact inoffensif servant de référence.

Le serveur HTTP local se lance avec :

```powershell
.\run.bat lab-serve
```

Il écoute uniquement sur `127.0.0.1:8088`. Il omet volontairement plusieurs
en-têtes de sécurité. Dans un second terminal :

```powershell
.\run.bat scan 127.0.0.1 --ports 8088 --authorized
.\run.bat headers http://127.0.0.1:8088
```

Le but est double : vérifier que le scan détecte réellement un service local,
puis comprendre pourquoi CSP, `X-Content-Type-Options`, `Referrer-Policy` et
`Permissions-Policy` sont recommandés. La cible étant locale et connue, le
résultat est reproductible et ne dépend d'aucun site tiers.

Le journal et le payload peuvent être analysés ainsi :

```powershell
.\run.bat logs lab_workspace\journal_suspect.log
.\run.bat payload lab_workspace\payload_a_identifier.txt
.\run.bat script lab_workspace\script_a_auditer.py
```

### Analyses complémentaires

- résolution DNS et comparaison des adresses obtenues ;
- inspection du protocole, du chiffrement et de l'expiration TLS ;
- intégrité SHA-256, SHA-512 ou BLAKE2 d'un fichier ;
- audit local du système et analyse d'en-têtes HTTP ;
- permissions de fichiers et détection de types sensibles ;
- audit du `PATH` et présence de noms de variables sensibles, sans lire leurs valeurs ;
- distinction entre Base64, hachage et chiffrement réversible ;
- analyse statique de scripts sans les exécuter.
- informations Wi-Fi exposées par Windows, NetworkManager ou Termux:API ;
- appareils Bluetooth déjà connus du système.

Exemples :

```powershell
.\run.bat permissions README.md
.\run.bat config
.\run.bat encoding encode "bonjour"
.\run.bat encoding encrypt "message" --key "cle-demo"
.\run.bat script chemin\vers\script.py
.\run.bat wifi
.\run.bat bluetooth
```

Le chiffrement XOR proposé est exclusivement pédagogique : il montre qu'un
chiffrement est réversible avec une clé, mais il est impropre à la protection
de données réelles.

### Rapports

Par défaut, chaque atelier demande si un rapport Markdown doit être généré.
Le menu permet ensuite de :

- afficher un rapport dans le terminal ;
- supprimer un rapport après confirmation ;
- fusionner plusieurs rapports et ajouter une section de conclusion.
- exporter un rapport en JSON ou en HTML.

Les rapports de mission et de journaux incluent un résumé exécutif, le
périmètre, la sévérité, les preuves, les impacts, les recommandations et les
limites de l'analyse.

## Paramètres

Le menu **Paramètres** enregistre les préférences dans `.cybertoolbox.json` :

- langue du menu et des confirmations principales : français ou anglais ;
- rapports : `ask`, `auto` ou `off` ;
- ports utilisés par défaut ;
- préférence pour Nmap ou le mode portable ;
- affichage des explications pédagogiques ;
- corrélation DNS du nom d'un appareil, uniquement après activation ;
- délai des connexions TCP.

Le fichier est local et ignoré par Git. Le mode `ask` est utilisé par défaut :
aucun rapport n'est créé sans confirmation. `auto` active la génération
automatique et `off` la désactive.

La corrélation réseau/Internet reste limitée à des informations techniques,
comme la résolution DNS d'un nom explicitement fourni. Elle ne recherche pas de
comptes personnels et n'envoie pas automatiquement une MAC à un service tiers.

La commande suivante affiche un résumé directement dans l'application :

```powershell
.\run.bat overview
```

## Wi-Fi et Bluetooth

Les commandes `wifi` et `bluetooth` lisent uniquement les informations
autorisées par le système :

- Windows : `netsh` et liste des périphériques Bluetooth connus ;
- Linux : `nmcli`, `iwgetid` et `bluetoothctl` lorsqu'ils sont installés ;
- Termux : informations Wi-Fi si Termux:API et les permissions Android sont
  disponibles.

Elles ne capturent pas les paquets, ne forcent pas une association et ne
permettent pas de suivre secrètement un appareil. Android peut limiter fortement
ces informations selon sa version et ses permissions.

## Installation rapide

### Windows

Téléchargez puis décompressez le projet, ou clonez-le avec Git. Dans le dossier
`toolbox`, double-cliquez sur :

```text
install.bat
```

Puis utilisez :

```text
run.bat
```

Depuis PowerShell ou l'invite de commandes, cela revient à :

```powershell
.\install.bat
.\run.bat
```

L'installateur :

- détecte une installation Python fonctionnelle ;
- peut proposer Python 3.12 via `winget` s'il manque ;
- remplace automatiquement un environnement `.venv` inutilisable ;
- crée et vérifie le nouvel environnement.

Il n'utilise aucun script PowerShell : la politique d'exécution Windows ne
bloque donc pas l'installation.

### Linux et macOS

```bash
git clone https://github.com/MWillem/toolbox.git
cd toolbox
sh install.sh
sh run.sh
```

Python 3.10 ou plus récent doit être installé sur la machine.

Nmap est recommandé :

```bash
# Debian, Ubuntu, Kali
sudo apt install nmap

# macOS avec Homebrew
brew install nmap
```

Sur Windows, installez Nmap depuis son installateur officiel et vérifiez que la
commande `nmap` est disponible dans le terminal.

### Android avec Termux

Installez Termux depuis F-Droid, puis :

```bash
pkg update
pkg install python git nmap
git clone https://github.com/MWillem/toolbox.git
cd toolbox
sh install.sh
sh run.sh
```

L'application ne demande pas d'accès root.

## Lancement

Les lanceurs fonctionnent sans activer manuellement l'environnement virtuel :

```bash
# Windows
.\run.bat

# Linux, macOS ou Termux
sh run.sh
```

Ils acceptent également les commandes directes :

```powershell
.\run.bat manual
.\run.bat scan 192.168.1.10 --ports 1-1024 --authorized
```

```bash
sh run.sh manual
sh run.sh scan 192.168.1.10 --ports 1-1024 --authorized
```

## Commandes directes

```bash
# Découverte d'un réseau privé autorisé
run.bat discover 192.168.1.0/24 --authorized

# Scan de ports avec Nmap si disponible
run.bat scan 192.168.1.10 --ports 1-1024 --authorized

# Lab hors ligne sur un hash et une petite wordlist
run.bat crack HASH_SHA256 labs/wordlists/demo.txt

# Analyse statique d'un fichier
run.bat payload chemin/vers/fichier

# Manuel et rapports
run.bat manual
run.bat reports

# Mission guidée
run.bat mission

# Laboratoire local
run.bat lab-prepare
run.bat lab-serve

# Journaux, DNS et TLS
run.bat logs lab_workspace\journal_suspect.log
run.bat dns example.org
run.bat tls example.org
```

Sur Linux, macOS ou Termux, remplacez `run.bat` par `sh run.sh`.

## Cadre d'utilisation

La découverte et le scan n'acceptent que les adresses locales ou les réseaux
IPv4 privés. Une confirmation d'autorisation est exigée.

N'utilisez jamais la toolbox sur un système tiers sans autorisation explicite.
Le scan lui-même n'est pas une preuve de vulnérabilité : les résultats doivent
être vérifiés, contextualisés et documentés.

## Tests

```bash
python -m unittest discover -s tests -v
```

Une CI GitHub teste le projet sous Windows, Linux et macOS avec Python 3.10 et
Python 3.12.
