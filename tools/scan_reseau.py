#!/usr/bin/python3

from scapy.all import ARP, Ether, srp
import json

def scan_reseau(adresse_ip):
    arp = ARP(pdst=adresse_ip+"/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet = ether/arp

    reponse, _ = srp(paquet, timeout=2, verbose=False)

    adresses_ip = set()
    for _, reponse in reponse:
        adresses_ip.add(reponse.psrc)

    return list(adresses_ip)

def scan_reseau_et_generer_json(adresse_ip):
    adresses_ip = scan_reseau(adresse_ip)
    resultats = {"adresse_ip": adresse_ip, "adresses_trouvees": adresses_ip}
    return json.dumps(resultats, indent=4)
