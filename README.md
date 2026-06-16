# Cyber Learning Toolbox

Projet original conçu et maintenu par **Maréchaux Willem**.
Copyright © 2026 Maréchaux Willem. Distribué sous licence MIT : les copies et
redistributions substantielles doivent conserver la notice de copyright et la
licence. Voir [`LICENSE`](LICENSE) et [`NOTICE`](NOTICE).

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

Le menu terminal nettoie l'écran entre les modules. Il détecte aussi la largeur
disponible : les grandes bannières ASCII sont conservées sur un écran large et
remplacées par des titres compacts sur téléphone ou dans une fenêtre étroite.

## Menu principal

```text
  _____ ___   ___  _     ____   _____  __
 |_   _/ _ \ / _ \| |   | __ ) / _ \ \/ /
   | || | | | | | | |   |  _ \| | | \  /
   | || |_| | |_| | |___| |_) | |_| /  \
   |_| \___/ \___/|_____|____/ \___/_/\_\

1. Tableau de bord
2. Opérations guidées
3. Reconnaissance et profils
4. Laboratoires pédagogiques
5. Wi-Fi et Bluetooth
6. Données, rapports et exposition
7. Interface graphique
8. Paramètres, manuel et outils
```

Les sous-menus suivent la même logique dans le terminal et dans la GUI :

- **Dashboard** : heure, fuseau, plateforme, historiques, rapports et météo facultative ;
- **Opérations** : mission guidée et mode Watchdog ;
- **Recon** : découverte, ports, profiler, aide et exposition ;
- **Labs** : mots de passe, WPA2, HTTP, journaux, payloads et scripts ;
- **Sans-fil** : Wi-Fi, Bluetooth, diagnostic et profil local ;
- **Données** : historiques, missions, rapports, comparaison et suppression ;
- **Outils** : système, hash, DNS, TLS, permissions et configuration.

## Interface graphique

Le menu principal propose une interface web locale responsive inspirée des
consoles de surveillance technologique. Le thème combine une vue d'applications
sur téléphone et une console tactique sur PC, avec noir, gris, magenta et vert.
Il utilise une identité originale : aucun logo ou ressource des jeux de
référence n'est intégré.

Le menu latéral fonctionne comme un tiroir hamburger et peut rester masqué.
L'onglet **Apparence** des réglages propose plusieurs palettes : violet, bleu
GitHub, vert terminal, bleu océan et ambre. L'effet glassmorphism ajoute des
panneaux translucides et floutés ; il peut être désactivé avec un interrupteur.

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

La page `http://127.0.0.1:8765` s'ouvre dans le navigateur. Elle regroupe les
modules par usage : opérations guidées, reconnaissance, profiler, laboratoires,
Wi-Fi/Bluetooth, exposition locale, carte tactique, données, outils, contexte et
réglages. Les conditions d'utilisation doivent être acceptées avant d'accéder
aux modules.

Les outils système, hash, DNS, TLS, configuration, permissions, journaux,
scripts, payloads factices, mots de passe et Base64 sont utilisables dans la
GUI. Pour protéger la machine qui héberge l'interface, les analyses de fichiers
du GUI sont limitées au dossier de la toolbox.

Pendant une reconnaissance ou une autre opération longue, un panneau affiche
le temps écoulé et les étapes de traitement en cours. Les listes structurées,
comme les hôtes, ports ou services, utilisent des tableaux aux colonnes alignées
sur PC comme sur téléphone.

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

### Dashboard et contexte

Le terminal et la GUI affichent l'heure locale, la date, le fuseau horaire et
la plateforme. La météo est facultative : elle n'est chargée qu'après saisie de
coordonnées ou autorisation de la géolocalisation dans le navigateur.

La météo utilise l'API Open-Meteo. Les coordonnées servent uniquement à la
requête demandée et ne sont pas enregistrées par la toolbox.

La géolocalisation est demandée par le navigateur et reste facultative. Sur un
téléphone, elle peut nécessiter l'autorisation Android correspondante.

### Cartographie

La page Carte possède deux onglets complémentaires :

- **Carte géographique** : une carte OpenStreetMap interactive centrée sur des
  coordonnées saisies ou sur la position explicitement autorisée dans le
  navigateur, avec recherche d'adresse, zoom, déplacement, recentrage sur le
  marqueur, fonds standard ou topographique, et itinéraire indicatif lorsque
  le service externe répond ;
- **Topologie réseau** : une carte SVG construite à partir des scans de ports
  conservés.

La position géographique n'est pas enregistrée. Les appareils découverts sur le
réseau ne sont jamais placés automatiquement sur cette carte.

La toolbox utilise deux rendus basés sur les données OpenStreetMap : Standard
et OpenTopoMap. Le fond topographique peut afficher le relief et les courbes de
niveau selon les données disponibles.

Dans la topologie réseau :

- la toolbox est placée au centre ;
- chaque actif autorisé devient un nœud ;
- le nombre de services observés est affiché ;
- une bordure orange signale un service à vérifier.

Cette carte est schématique, comme une vue tactique. Elle n'affiche pas la
position physique d'une personne ou d'un appareil.

### Réseaux Wi-Fi visibles

Sur Windows, la toolbox utilise `netsh wlan show networks mode=bssid` pour
demander les réseaux visibles, y compris ceux auxquels le PC n'est pas connecté.
Le réseau actif est marqué `connected: true`.

Les versions récentes de Windows protègent ces informations par l'autorisation
de localisation. Si seul le réseau connecté apparaît :

1. ouvrir **Paramètres > Confidentialité et sécurité > Localisation** ;
2. activer les services de localisation ;
3. autoriser les applications de bureau à accéder à la localisation ;
4. relancer le scan Wi-Fi, éventuellement depuis un terminal administrateur si
   Windows le demande explicitement.

Sans cette permission, la toolbox indique que le scan est incomplet et affiche
seulement le réseau connecté lorsqu'il reste accessible.

### Inventaire d'exposition local

La page **Exposition locale** offre un inventaire défensif : actifs, services,
dernières observations et points d'attention. Elle ne scanne pas Internet. Elle
indexe uniquement les résultats privés et autorisés déjà conservés dans
`historique/`.

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

Depuis le menu, une découverte peut être conservée dans l'historique local.
Lors d'un scan de ports ultérieur, il est alors possible de sélectionner
directement un des hôtes déjà découverts au lieu de ressaisir son adresse.

### Scan de ports

Lorsque Nmap est disponible, `nmap -sV` identifie les ports ouverts, les
services, produits et versions. Le repli portable utilise des connexions TCP
Python, avec moins d'informations.

Le sous-menu propose aussi :

- une fiche d'aide sur les ports courants et les services généralement associés ;
- la reprise d'un ancien scan avec la même cible et la même sélection de ports ;
- la comparaison avec le dernier scan conservé de la cible ;
- l'affichage des ports nouvellement ouverts, fermés ou dont le service a changé.

Chaque résultat peut être conservé comme une nouvelle fiche, renommé ou ignoré.
Une nouvelle fiche ne remplace jamais automatiquement l'ancienne.

### Historique local

Les découvertes et scans conservés sont enregistrés dans `historique/`, au
format JSON. Ce dossier reste local et est ignoré par Git. Le menu
**Données enregistrées** permet de :

- consulter une fiche et ses résultats ;
- renommer son libellé ;
- supprimer une fiche ;
- supprimer toute une catégorie ;
- consulter, renommer ou supprimer les missions guidées sauvegardées ;
- supprimer en une seule fois les historiques, rapports et missions.

La gestion des rapports permet également de renommer un fichier ou de supprimer
tous les rapports et leurs exports HTML/JSON après confirmation explicite.

Dans l'interface graphique, la page **Données** regroupe les onglets Rapports,
Historiques, Missions et Nettoyage. Chaque élément peut être renommé ou supprimé,
et l'effacement global demande une confirmation explicite.

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

Le menu **Wi-Fi et Bluetooth pédagogiques** propose :

- un scan en lecture seule des réseaux Wi-Fi visibles ;
- SSID, BSSID, canal, fréquence, signal et sécurité annoncée lorsqu'ils sont disponibles ;
- une explication des réseaux ouverts, WEP, WPA2 et WPA3 ;
- les appareils Bluetooth connus ou visibles exposés par le système ;
- l'opérateur mobile du téléphone Android qui exécute la toolbox ;
- un diagnostic des outils, permissions et limites du matériel ;
- un laboratoire WPA2 entièrement hors ligne.

Les moteurs utilisés sont :

- Windows : `netsh` et `Get-PnpDevice` ;
- Linux : `nmcli` et `bluetoothctl` ;
- Android avec Termux : `termux-wifi-scaninfo` et
  `termux-telephony-deviceinfo` avec Termux:API.

Elles ne capturent pas les paquets, ne forcent pas une association et ne
permettent pas de suivre secrètement un appareil. Android peut limiter fortement
ces informations selon sa version et ses permissions.

### Utilisation sur Termux

Installer l'application **Termux:API** depuis la même source que Termux, puis :

```bash
pkg update
pkg install termux-api
termux-wifi-scaninfo
termux-telephony-deviceinfo
sh run.sh
```

Android peut demander les permissions de localisation ou d'appareils à
proximité. Sur certaines versions, le service de localisation doit également
être activé. La 4G/5G peut rester active : elle n'empêche pas l'observation des
réseaux Wi-Fi proches.

Voir un réseau n'autorise pas à le tester. Pour une démonstration, sélectionner
uniquement le point d'accès de laboratoire fourni et autorisé.

### Opérateur Internet et opérateur mobile

Le nom d'un point d'accès, son BSSID, son fabricant probable et certains noms
réseau peuvent donner un **indice** sur le fournisseur d'accès Internet. Ce
n'est pas une preuve : le SSID peut être modifié, le routeur remplacé ou utilisé
derrière un autre opérateur.

Sur Android, `termux-telephony-deviceinfo` permet d'afficher l'opérateur du
réseau mobile et celui de la SIM du **téléphone qui exécute la toolbox**. La
toolbox filtre les identifiants d'appareil, de SIM et d'abonné. Android peut
demander l'autorisation Téléphone.

Il n'est pas possible de déterminer de façon fiable l'opérateur mobile d'un
téléphone tiers simplement parce qu'il apparaît sur un réseau Wi-Fi ou en
Bluetooth. Le Wi-Fi et le réseau cellulaire sont deux interfaces distinctes.

### Organisation des modules

Plusieurs écrans utilisent les mêmes informations, mais n'ont pas le même rôle :

- **Collecte** : découverte d'hôtes, ports, Wi-Fi et Bluetooth ;
- **Orchestration** : Mission guidée et Watchdog enchaînent les collectes ;
- **Enrichissement** : Profiler interprète noms, services, fabricant et type probable ;
- **Restitution** : Carte, Exposition, Historique et Rapports présentent les données.

Le principal chevauchement restant est le scan de ports relancé par le Profiler.
Les autres répétitions correspondent surtout à des vues ou parcours différents
sur une collecte commune.

### Laboratoire WPA2 hors ligne

Le laboratoire demande :

1. un SSID fictif ou celui du point d'accès temporaire du laboratoire ;
2. un mot de passe temporaire choisi pour la démonstration ;
3. une petite liste locale de candidats.

Il reproduit la dérivation WPA2 `PBKDF2-HMAC-SHA1` avec 4096 itérations. Il ne
se connecte à aucun réseau, ne capture aucun paquet et ne désauthentifie aucun
appareil. Le mot de passe retrouvé est affiché pendant la session, mais le
rapport conserve uniquement le résultat, le nombre d'essais et la durée.

```powershell
.\run.bat wifi-lab
```

### Profiler enrichi

Le profil technique d'un appareil autorisé cherche son nom à travers plusieurs
sources disponibles :

- nom fourni lors de la sélection ;
- DNS inverse ;
- mDNS avec Avahi sur les systèmes compatibles ;
- NetBIOS sur certains équipements Windows ;
- nom Bluetooth dans l'inventaire séparé lorsque le système l'expose.

Chaque nom est accompagné de sa source et d'un niveau de confiance. Les noms
radio et réseau sont déclaratifs : ils peuvent être modifiés et ne prouvent
jamais l'identité du propriétaire.

Le mode Watchdog contient également un **profil technique de l'environnement**.
Il décrit l'appareil qui exécute la toolbox, les réseaux Wi-Fi visibles et les
appareils Bluetooth exposés. Sur Termux, le modèle et le fabricant du téléphone
peuvent être lus localement avec `getprop`.

## Modules QR, NFC, hash et profiler enrichi

La version 2.13 ajoute cinq modules pédagogiques accessibles depuis les menus :

- **QR Codes** : texte, accès Wi-Fi, vCard, lecture d'image et leçon phishing ;
- **NFC** : scan Termux/libnfc, analyse NDEF, écriture d'URL si un outil
  compatible est installé et sauvegarde documentaire d'un tag ;
- **Hash enrichi** : MD5, SHA-1/2/3, BLAKE2b, NTLM, identification de format et
  attaque par dictionnaire locale ;
- **Bluetooth avancé** : découverte classique, BLE, fabricant OUI et profil
  technique d'un appareil ;
- **Profiler Watch Dogs** : recherche HEAD limitée d'un username public, profil
  de l'environnement et score pédagogique d'ombre numérique.

Les fonctions NFC et Bluetooth avancées dépendent du matériel, des pilotes, des
permissions et des outils disponibles. L'absence d'un appareil dans un scan ne
prouve pas son absence physique.

La recherche d'un username vérifie uniquement les URL publiques explicitement
prévues pour GitHub, Twitter/X, Instagram, Reddit et Twitch. Elle n'effectue pas
de scraping, ne recherche pas d'email ou de téléphone et ne prouve pas
l'identité du propriétaire d'un compte.

Le « score d'ombre numérique » représente la quantité d'informations techniques
observables. Il ne constitue ni un score de dangerosité, ni une preuve de
compromission.

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
