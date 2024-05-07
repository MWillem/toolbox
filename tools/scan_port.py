#!/usr/bin/python3

import nmap
import json

def scan_ports_et_generer_json(ip_address):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-sV -Pn')

    results = []

    # Récupérer les résultats du scan
    for host in nm.all_hosts():
        host_data = {"host": host, "ports": []}

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()

            for port in ports:
                port_state = nm[host][proto][port]['state']

                if port_state == 'open':
                    port_data = {
                        "port": port,
                        "state": port_state,
                        "service": nm[host][proto][port]['name'],
                        "version": nm[host][proto][port]['version']
                    }
                    host_data["ports"].append(port_data)

        results.append(host_data)

    return json.dumps(results, indent=4)
