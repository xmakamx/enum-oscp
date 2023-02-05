#!/bin/bash
# Subscript of osint-blackbox
# Environment variables:

bold=$(tput bold)
normal=$(tput sgr0)
script=$(echo -n $PWD)
TARGET=$(cat ../project.txt)
IPScope=$TARGET/IPscope.txt

	if [ ! -d $TARGET/autorecon ]; then
		mkdir $TARGET/autorecon
	fi

	echo "[*] IPScope.txt"
		cat $IPScope
	echo
	echo "[+] Processing: ${bold} AutoRecon"
	if [ -f /home/*/.local/bin/autorecon ]; then
		sudo /home/*/.local/bin/autorecon -t $IPScope -o $TARGET/autorecon
	else
	sudo /root/.local/bin/autorecon -t $IPScope -o $TARGET/autorecon
	fi
	done
	echo "[FINISHED] ${normal} AutoRecon"
