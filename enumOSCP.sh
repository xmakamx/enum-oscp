#!/bin/bash
# Created by Martijn Kamminga
# v1.0 on 10/15/2022
# www.isee2it.nl

scriptlocation=$(echo -n $PWD)
PROJECT=$(cat $scriptlocation/project.txt)
IPScope=$PROJECT/IPscope.txt


quit() {
echo "Do you want to quit ? (y/n)"
  read ctrlc
  if [ "$ctrlc" = 'y' ]; then
    exit
  fi
}

trap quit SIGINT
trap quit SIGTERM

function pause(){
   read -p "$*"
}

Help()
{
   # Display Help
	echo "**************           Requirements to run smoothly         ************** "
	echo "**************           Syntax: enum-oscp.sh [-h,-r]         ************** "
	echo "**************           Options:                             ************** "
	echo "**************           r     Requirements needed            ************** "
}

Requirements()
{
# cat requirements.sh
read -p "Install Requirements (y/n)?" choice
case "$choice" in
  y|Y ) sudo bash requirements.sh;;
  n|N ) echo "Discarding" && exit 0;;
  * ) echo "Invalid";;
esac
}

while getopts ":h,-r" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      r) # display requirements
         Requirements
         exit;;
     \?) # incorrect option
         echo "Error: Invalid option"
         exit;;
   esac
done

logo(){
	echo -e "\e[96m     ____   _____  _____ _____     ______                            ";
	echo -e "\e[96m    / __ \ / ____|/ ____|  __ \   |  ____|                           ";
	echo -e "\e[96m   | |  | | (___ | |    | |__) |  | |__   _ __  _   _ _ __ ___       ";
	echo -e "\e[96m   | |  | |\___ \| |    |  ___/   |  __| | '_ \| | | | '_   _ \      ";
	echo -e "\e[96m   | |__| |____) | |____| |       | |____| | | | |_| | | | | | |     ";
	echo -e "\e[96m    \____/|_____/ \_____|_|       |______|_| |_|\__,_|_| |_| |_|     ";
	echo -e "\e[96m ";
	echo -e "\e[96m \e[0m ";
	echo -e "\e[96m              Follow me on twitter: @xmakamx \e[0m ";
	echo
	echo "Syntax: bash enum-oscp.sh [-h,-r] (help/requirements)"
}
logo

# Fonts
bold=$(tput bold)
normal=$(tput sgr0)
date=$(TZ="CET" date '+%Y-%m-%d-%H-%M-%S')

echo ""
echo "[i] The Date Timestamp is: `date`"


FirstRun() {
if [[ $(< $scriptlocation/firstrun.txt) == "true" ]]; then
read -p "[-]It looks like you have not ran this script before. Do you wish to install the requirements? (mandatory) (y/n)?" choice
echo '[+] Want to ignore this message? Execute: echo "false" >> firstrun.txt'
case "$choice" in
  y|Y ) bash requirements.sh -r;;
  n|N ) echo "Discarding" && exit 0;;
  * ) echo "Invalid";;
esac
fi
}

FirstRun

Commands(){
echo "[+] You can call $PWD/oscpcmd.sh directly from this directory"
bash oscpcmd.sh && sleep 2
exit
}

function nmaptrue() {
touch $scriptlocation/activescan.txt
echo "true" > $scriptlocation/activescan.txt
}

Quit() {
exit
}

Process() {

	touch $scriptlocation/executed.txt
	echo "Project started on: `date`" >> $scriptlocation/executed.txt

echo
echo "[+] Provide the working directory: e.g. "/home/kali/project" (without the trailing slash):"
read project

echo $project > $scriptlocation/project.txt

echo "IPscope.txt"
read -p "Please Enter the IP Addresses:"$'\n' IPscope
echo $IPscope | sed 's/, /\n/g' | sed 's/,/\n/g' | sed 's/;/\n/g' | sed 's/^"//' | sed 's/"$//' | sed 's/ /\n/g' > $scriptlocation/vars/IPscope.txt
echo "IPscope.txt filled with the following data"
cat $scriptlocation/vars/IPscope.txt

PROJECT=$(cat $scriptlocation/project.txt)

EXTIPscope=$scriptlocation/vars/IPscope.txt
touch $PROJECT/IPscope.txt
yes | cp -rf $EXTIPscope $PROJECT/IPscope.txt
EXTIPscope=$PROJECT/IPscope.txt

}

Process

Scan() {

nmaptrue

	echo "[+] Converting files to unix format"
	for file in $(find $scriptlocation/*.txt -type f); do dos2unix $file > /dev/null 2>&1; done
	for file in $(find $(pwd)/scripts -type f); do dos2unix $file > /dev/null 2>&1; done
	dos2unix $PROJECT/IPscope.txt > /dev/null 2>&1

	scriptlocation=$(echo -n $PWD)
	PROJECT=$(cat $scriptlocation/project.txt)
	cd $scriptlocation
	cd scripts/
	for script in $(ls -p *.sh | grep -v /); do bash $script && sleep 2;done
	echo "Project finished on: `date`" >> $scriptlocation/executed.txt
	ls -lah -R 
	exit
}

SummaryChoice() {
	# BASE WORKING FOLDER:
	touch $scriptlocation/executed.txt
	echo "[+] The Date Timestamp is: `date`" >> $scriptlocation/executed.txt
	echo
	echo "[+] Overview:                  "
	echo "[+] Project folder            :" $project
	echo "[+] External IP Scope         :" $EXTIPscope
	echo

	echo "[+] Choose you type of scan"
	echo
	echo "[1] Scan"
	echo "[2] Quit"

read -p "[+] Choices: (1/2) : " choice
case "$choice" in
  1 ) Scan ;;
  2 ) Quit ;;
  * ) echo "Invalid";;
esac
}

TakeMeOut() {
	echo "[+] Do you wish to scan or see commands?"
	echo
	echo "[1] Take me to the Scans"
	echo "[2] Take me to the Commands"

read -p "[+] Choices: (1/2) : " choice
case "$choice" in
  1 ) SummaryChoice ;;
  2 ) Commands ;;
  * ) echo "Invalid";;
esac
}

TakeMeOut
