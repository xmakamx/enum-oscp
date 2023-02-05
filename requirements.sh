#!/bin/bash
scriptlocation=$(echo -n $PWD)
sudo apt-get purge apt-file
sudo apt update
sudo apt install python3
sudo apt install python3-pip
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
sudo apt install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath

echo "false" > $scriptlocation/firstrun.txt exit
bash $scriptlocation/enumOSCP.sh

