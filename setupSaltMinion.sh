#!/bin/bash
#==========Colors============
debugColor='\033[0;32m'
infoColor='\033[0;34m'
warningColor='\033[0;33m'
notifyColor='\033[1;31m'
NC='\033[0m'
#==========Execute===========
ExecuteSaltStackMinion="true"

function sleepForXSeconds(){
	sleepFor=$1
    	printf "${infoColor}${BOLD}[==========================]${NOBOLD}${NC}\n"
    	printf "${infoColor}${BOLD}[Safety Sleep for $sleepFor seconds]${NOBOLD}${NC}\n"
    	printf "${infoColor}${BOLD}[==========================]${NOBOLD}${NC}\n${LRED}${BOLD}"
    	for counter in `seq 0 $sleepFor`;
    	do
        	counter=$(( $sleepFor - $counter ))
        	echo -ne "Wait for: $counter \r"
        	sleep 1
    	done
    	printf "${NOBOLD}${NC}"
}

printf "\n${infoColor}[================================================]${NC}\n"
printf "${infoColor}[================[${notifyColor}Setup Script${infoColor}]==================]${NC}\n"
printf "${infoColor}[================[${notifyColor}Salt-Master${infoColor}]===================]${NC}\n"
printf "${infoColor}[================================================]${NC}\n"
printf "${infoColor}Made by ${NC}${notifyColor}Martijn Dijkstra${NC}\n\n"

#SALTSTACKMINION=====================================================================
if [ $ExecuteSaltStackMinion == "true" ]; then
	printf "${notifyColor}=====================================${NC}\n"
	printf "${notifyColor}Instalatie Saltstack Minion${NC}\n"
	printf "${notifyColor}=====================================${NC}\n"

		yes | sudo apt-get update
		printf "${infoColor}===[Curl installeren]===============${NC}\n"
		yes | sudo apt-get install curl
		sleepForXSeconds 3

		printf "${infoColor}Voor de installatie is het IP address van de master vereist.${NC}\n"
		read -p "Voer Master IP in: " masterIP

		printf "${infoColor}===[salt ophalen]======================${NC}\n"
		curl -L https://bootstrap.saltstack.com -o install_salt.sh

		printf "${infoColor}===[salt installeren met masterIP]=====${NC}\n"
		sudo sh install_salt.sh -A ${masterIP}
		rm install_salt.sh

		printf "${infoColor}===[salt minion service restart]=======${NC}\n"
		systemctl restart salt-minion.service
		sleepForXSeconds 10

	printf "${notifyColor}=====================================${NC}\n"
	printf "${notifyColor}Instalatie Saltstack Minion Voltooid!${NC}\n"
	printf "${notifyColor}=====================================${NC}\n"
else
	printf "${warningColor}[WARNING!]: SaltStack Minion wordt niet aangemaakt/geconfigureerd!${NC}\n"
fi
#SALTSTACKMINION=====================================================================







