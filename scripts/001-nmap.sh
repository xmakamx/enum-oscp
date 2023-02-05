#!/bin/bash
# Subscript of osint-blackbox
# Environment variables:

bold=$(tput bold)
normal=$(tput sgr0)
script=$(echo -n $PWD)
TARGET=$(cat ../project.txt)
IPScope=$TARGET/IPscope.txt

	nmapNFIR() { grep -hv "Status: Down\|Status: Up" $@ |grep "^#\|/open/" |sed s/'\t'/'\n\t'/g |sed s/'\/, '/'\n\t\t'/g |sed s/'Ports: '/'\n\t\t'/g |grep -v "/closed/\|filtered/"|sed "/Host:/ s=(\(.*\))=($(tput setaf 4)\1$(tput sgr0))=" |sed "s/Host:/$(tput setaf 1)&$(tput sgr0)/g" |sed "/\t\t/ s=\(\t\t[0-9]*\)=$(tput setaf 2)\1$(tput sgr0)=" |awk -F '/' '{OFS=FS; if (NF<2) {print;next} else $7="\033[01;33m"$7"\033[00m";print}' |sed "/OS:/ s= .*=$(tput setaf 5)&$(tput sgr0)=" |sed "s/^#.*/$(tput setaf 6)&$(tput sgr0)/" | sed 's/Host:/''/g' | sed -e 's/\/\// /g' | sed 's/\Ignored State: filtered (65533)'/''/g| sed "s/|/\t/g"| sed "s/\/tcp/\t/g"; } 

	if [ ! -d $TARGET/nmap ]; then
		mkdir $TARGET/nmap
	fi

	echo "[*] IPScope.txt"
		cat $IPScope
	echo
	echo "[+] Processing: ${bold}NMAP Full"
	for host in $(cat $IPScope); do
		sudo nmap -Pn -p- -T 4 $host -oA $TARGET/nmap/TCPAllPorts_$host
		cat $TARGET/nmap/TCPAllPorts_$host.nmap | grep 'open' | sed 's/\/tcp*//g' | awk '{print $1}' | tr '\n' ',' | sed 's/,$//' > $TARGET/nmap/ServicePorts.txt
		SvcPorts=`cat $TARGET/nmap/ServicePorts.txt`
		sudo nmap -Pn -p $SvcPorts -sVC -T 4 $host -oA $TARGET/nmap/TCPAllServicePorts_$host
		sudo nmap -Pn -p- -sU -T 4 $host -oA $TARGET/nmap/nmapUDPAllPorts_$host
	echo "Sorting console output"
		nmapNFIR $TARGET/nmap/TCPAllPorts_$host.gnmap >> $TARGET/nmap/TCPAllPorts_$host.txt
		nmapNFIR $TARGET/nmap/TCPAllServicePorts_$host.gnmap >> $TARGET/nmap/TCPAllServicePorts_$host.txt
		nmapNFIR $TARGET/nmap/UDPAllPorts_$host.gnmap >> $TARGET/nmap/UDPAllPorts_$host.txt
		cat $TARGET/nmap/*.txt
	done
	echo "[FINISHED] ${normal}NMAP Full"

