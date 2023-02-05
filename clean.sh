#!/bin/bash
scriptlocation=$(echo -n $PWD)
echo "[i] Cleaning files"
truncate -s 0 $scriptlocation/*.txt
truncate -s 0 $scriptlocation/vars/*.txt
rm -f $scriptlocation/nmap/*.*
rm -f $scriptlocation/results/*.*
echo "true" > $scriptlocation/firstrun.txt
echo "[+] Clean Finished"
