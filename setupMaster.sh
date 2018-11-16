#!/bin/bash
#==========Colors=======================
debugColor='\033[0;32m'
infoColor='\033[0;34m'
warningColor='\033[0;33m'
notifyColor='\033[1;31m'
LGREEN='\033[1;32m'
BOLD="\e[1m"
NC='\033[0m'
#==========Execute======================#
ExecutePackages="false"			#CHECK (GEEN FOUTEN)								#X
ExecuteSaltMaster="false"		#CHECK (SALTSTACK werkt ping werkt met minion)					#Service Werkt
ExecuteDocker="false"			#-----
ExecuteElasticS="false"			#CHECK (Klein foutje bij ophalen key (geen internet?) 2e keer werkt wel)	#Service Werkt
ExecuteKibana="false"			#CHECK (GEEN FOUTEN)								#Service Werkt
ExecuteNGNIX="false"			#CHECK (GEEN FOUTEN) alleen wachtwoord moet ingevuld worden			#Service werkt localhost:5601 werkt
ExecuteLogStash="false"			#CHECK (GEEN FOUTEN) later pas service check					#X
ExecuteGenCert="false"			#CHECK (GEEN FOUTEN) alleen weet niet of cert nu goed is			#X
ExecuteConfigLogSt="false"		#CHECK (GEEN FOUTEN) blijft alleen enable niet kunnen uitvoeren			#Service Werkt
ExecuteLoadKibanaDash="false"		#CHECK (GEEN FOUTEN)								#X
ExecuteLoadFileBeatElastic="false"	#CHECK (GEEN FOUTEN)								#X
ExecuteSetupFileBeat="true"		#
ExecuteKubernetes="false"		#

#==========Interne Variabelen=======
#enp0s3
masterIP=$(ifconfig enp0s3 | grep "inet addr" | cut -d ':' -f 2 | cut -d ' ' -f 1)
username="masterserver"

function sleepForXSeconds(){
    sleepFor=$1
        printf "${infoColor}${BOLD}[================================================]${NC}\n"
        printf "${infoColor}${BOLD}[Safety Sleep for $sleepFor seconds]${NOBOLD}${NC}\n"
        printf "${infoColor}${BOLD}[================================================]${NOBOLD}${NC}\n${LRED}${BOLD}"
        for counter in `seq 0 $sleepFor`;
        do
            counter=$(( $sleepFor - $counter ))
            echo -ne "Wait for: $counter \r"
            sleep 1
        done
        printf "${NOBOLD}${NC}"
}
function printStartEnd(){
	input=$1
	name=$2
	startzin="Leeg"

	if [ $1 == "start" ]; then
		startzin="Start" 
	elif [ $1 == "end" ]; then
		startzin="Einde"
	else
		startzin="BAD INPUT" 
	fi		    
	printf "${infoColor}==================================================${NC}\n"
	printf "${notifyColor}$startzin Installatie: [${BOLD}$name${NC}${notifyColor}]${NC}\n"
	printf "${infoColor}==================================================${NC}\n"
}	
function printLineBetweenCode(){
	commandUitleg="=[${1}]"
	lengthString=$(echo $commandUitleg | awk '{print length}')
	verschil=$((50-$lengthString))
	while [ $verschil -gt 0 ]; do
		commandUitleg="${commandUitleg}="
		((verschil-=1))
	done
	printf "${LGREEN}$commandUitleg${NC}\n"
}

printf "\n${infoColor}[================================================]${NC}\n"
printf "${infoColor}[================[${notifyColor}Setup Script${infoColor}]==================]${NC}\n"
printf "${infoColor}[================[${notifyColor}Salt-Master${infoColor}]===================]${NC}\n"
printf "${infoColor}[================================================]${NC}\n"
printf "${infoColor}Made by ${NC}${notifyColor}Martijn Dijkstra${NC}\n\n"

printf "${infoColor}Voor de installatie is het IP address van de minion vereist.${NC}\n"
read -p "Voer Minion IP in: " minionIP
#minionIP="10.0.2.13"

#PACKAGES=====================================================================================
if [ $ExecutePackages == "true" ]; then
	printStartEnd "start" "Packages"

		printLineBetweenCode "Update"
		sudo apt-get update
		#SaltStack en Docker
		printLineBetweenCode "Curl"
		yes | sudo apt-get install curl
		sleepForXSeconds 3
		#Docker
		printLineBetweenCode "apt-transport-https"
		yes | sudo apt-get install apt-transport-https
		sleepForXSeconds 3
		#Docker
		printLineBetweenCode "ca-certificates"
		yes | sudo apt-get install ca-certificates
		sleepForXSeconds 3
		#Docker
		printLineBetweenCode "software-properties-common"
		yes | sudo apt-get install software-properties-common
		sleepForXSeconds 3
		#Elastic
		printLineBetweenCode "dpkg"
		yes | sudo apt-get install dpkg
		sleepForXSeconds 3
		#Elastic
		printLineBetweenCode "default-jre"
		yes | sudo apt-get install default-jre
		sleepForXSeconds 3
		#Elastic
		printLineBetweenCode "default-jdk"
		yes | sudo apt-get install default-jdk
		sleepForXSeconds 3
		#KibanaDashboard
		printLineBetweenCode "unzip"
		yes | sudo apt-get install unzip
		sleepForXSeconds 3

	printStartEnd "end" "Packages"
else
	printf "${warningColor}[WARNING!]: Packages worden niet geinstalleerd!${NC}\n"
fi
#PACKAGES=====================================================================================
#SALTSTACK====================================================================================
if [ $ExecuteSaltMaster == "true" ]; then
	printStartEnd "start" "SaltStack"

		printLineBetweenCode "Salt Ophalen"
		curl -L https://bootstrap.saltstack.com -o install_salt.sh

		printLineBetweenCode "Salt Installeren"
		sudo sh install_salt.sh -M
		rm install_salt.sh

		printLineBetweenCode "Alle keys accepteren"
		yes | sudo salt-key --accept-all

		printLineBetweenCode "Overzicht alle keys"
		sudo salt-key --list all

	printStartEnd "end" "SaltStack"
else
	printf "${warningColor}[WARNING!]: SaltStack wordt niet geinstalleerd${NC}\n"
fi
#SALTSTACK=================================================================================
#DOCKER====================================================================================
if [ $ExecuteDocker == "true" ]; then
	printStartEnd "start" "Docker"
		
		printLineBetweenCode "Docker Ophalen"
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

		printLineBetweenCode "Docker repository toevoegen"
		sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
		printLineBetweenCode "Update"
		sudo apt-get update

		printLineBetweenCode "Docker versie 18.06.1 installeren"
		sudo apt-get install -y docker-ce=18.06.1~ce~3-0~ubuntu

	printStartEnd "end" "Docker"
else
	printf "${warningColor}[WARNING!]: Docker wordt niet geinstalleerd${NC}\n"
fi
#DOCKER====================================================================================
#ELASTICSEARCH=============================================================================
if [ $ExecuteElasticS == "true" ]; then
	printStartEnd "start" "ElasticSearch"

		printLineBetweenCode "Ophalen Key Elastic"
		wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

		printLineBetweenCode "X"
		echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
		
		printLineBetweenCode "Update"
		sudo apt-get update

		printLineBetweenCode "Installeren Elastic Search"
		yes | sudo apt-get -y install elasticsearch

		printLineBetweenCode "Config aanpassen naar Localhost"
		sed -i -e "s/# network.host: 192.168.0.1/network.host: localhost/g" /etc/elasticsearch/elasticsearch.yml

		printLineBetweenCode "Restart en Enable Service Elastic"
		sudo systemctl restart elasticsearch
		sudo systemctl daemon-reload
    		sudo systemctl enable elasticsearch

	printStartEnd "end" "ElasticSearch"
else
	printf "${warningColor}[WARNING!]: ElasticS wordt niet geinstalleerd${NC}\n"
fi
#ELASTICSEARCH=============================================================================
#KIBANA====================================================================================
if [ $ExecuteKibana == "true" ]; then
	printStartEnd "start" "Kibana"

		printLineBetweenCode "Ophalen Kibana"
		echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list

		printLineBetweenCode "Update"
		sudo apt-get update

		printLineBetweenCode "Installeren Kibana"
		sudo apt-get -y install kibana

		printLineBetweenCode "Config Kibana aanpassen naar localhost"
		sed -i -e "s/# server.host: \"0.0.0.0\"/server.host: localhost/g" /opt/kibana/config/kibana.yml

		printLineBetweenCode "Kibana Restarten"
		sudo systemctl daemon-reload
    		sudo systemctl enable kibana
    		sudo systemctl start kibana

		#http://localhost:5601  martijnadmin test

	printStartEnd "end" "Kibana"
else
	printf "${warningColor}[WARNING!]: Kibana wordt niet geinstalleerd${NC}\n"
fi
#KIBANA====================================================================================
#NGINX=====================================================================================
if [ $ExecuteNGNIX == "true" ]; then
	printStartEnd "start" "NGINX"

		printLineBetweenCode "Installeren NGINX"
		yes | sudo apt-get -y install nginx
		sudo -v

		printLineBetweenCode "Config aanpassen met wachtwoord"
		printf "${notifyColor}[LETOP!]: ===================================================${NC}\n"
		printf "${notifyColor}[LETOP!]: Voer nu het wachtwoord in voor de user: $username ${NC}\n"
		echo "$username:`openssl passwd -apr1`" | sudo tee -a /etc/nginx/htpasswd.users
echo "    server {
        listen 80;

        server_name $masterIP;

        auth_basic \"Restricted Access\";
        auth_basic_user_file /etc/nginx/htpasswd.users;

        location / {
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;        
        }
    }
" > /etc/nginx/sites-available/default

		printLineBetweenCode "Restart NGINX"
		sudo systemctl restart nginx

		printLineBetweenCode "Allow UWF"
		sudo ufw allow 'Nginx Full'

	printStartEnd "end" "NGINX"
else
	printf "${warningColor}[WARNING!]: NGINX wordt niet geinstalleerd${NC}\n"
fi
#NGINX=====================================================================================
#LOGSTASH==================================================================================
if [ $ExecuteLogStash == "true" ]; then
	printStartEnd "start" "LogStash"

		printLineBetweenCode "Ophalen LogStash"
		echo "deb http://packages.elastic.co/logstash/2.3/debian stable main" | sudo tee -a /etc/apt/sources.list

		printLineBetweenCode "Update"
		sudo apt-get update

		printLineBetweenCode "Install"
		sudo apt-get install logstash

	printStartEnd "end" "LogStash"
else
	printf "${warningColor}[WARNING!]: LogStash wordt niet geinstalleerd${NC}\n"
fi
#LOGSTASH==================================================================================
#GENERATECERT==============================================================================
if [ $ExecuteGenCert == "true" ]; then
	printStartEnd "start" "GenerateCert"

		printLineBetweenCode "Dirs maken voor de certificaten"
		sudo mkdir -p /etc/pki/tls/certs
    		sudo mkdir /etc/pki/tls/private

		printLineBetweenCode "IP-address master invoegen"
		#!!!!!!overschrijft meerdere altnames
		input="subjectAltName = IP: ${masterIP}"

		sed -i -e "s/# issuerAltName=issuer:copy/$input/g" /etc/ssl/openssl.cnf

		printLineBetweenCode "Certificaat invoegen"
		cd /etc/pki/tls
		sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
		cd /home/martijn-master/Desktop/

	printStartEnd "end" "GenerateCert"
else
	printf "${warningColor}[WARNING!]: GenerateCert wordt niet geinstalleerd${NC}\n"
fi
#GENERATECERT==============================================================================
#CONFIGLOGSTASH============================================================================
if [ $ExecuteConfigLogSt == "true" ]; then
	printStartEnd "start" "Config LogStash"

		printLineBetweenCode "Configuratie FIle van logstash vullen"
		touch /etc/logstash/conf.d/02-beats-input.conf
		echo "input {
      beats {
        port => 5044
        ssl => true
        ssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\"
        ssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\"
      }
    }
" >/etc/logstash/conf.d/02-beats-input.conf

		printLineBetweenCode "verkeer toestaan op poort 5044"
		sudo ufw allow 5044

		printLineBetweenCode "Filter Configuratie van logstash vullen"
		echo "filter {
      if [type] == \"syslog\" {
        grok {
          match => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}\" }
          add_field => [ \"received_at\", \"%{@timestamp}\" ]
          add_field => [ \"received_from\", \"%{host}\" ]
        }
        syslog_pri { }
        date {
          match => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ]
        }
      }
    }
" >/etc/logstash/conf.d/10-syslog-filter.conf

		printLineBetweenCode "Output Configuratie van logstash vullen"
		echo "output {
      elasticsearch {
        hosts => [\"localhost:9200\"]
        sniffing => true
        manage_template => false
        index => \"%{[@metadata][beat]}-%{+YYYY.MM.dd}\"
        document_type => \"%{[@metadata][type]}\"
      }
    }
" >/etc/logstash/conf.d/30-elasticsearch-output.conf
	
		printLineBetweenCode "Restart en enable de Logstash"
		sudo systemctl restart logstash
		sudo systemctl enable logstash

	printStartEnd "end" "Config LogStash"
else
	printf "${warningColor}[WARNING!]: Config LogStash wordt niet geinstalleerd${NC}\n"
fi
#CONFIGLOGSTASH============================================================================
#LOADKIBANADASH============================================================================
if [ $ExecuteLoadKibanaDash == "true" ]; then
	printStartEnd "start" "Load Kibana Dashboard"

		printLineBetweenCode "Download dashboard"
		cd ~
    		curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.2.2.zip

		printLineBetweenCode "Unzip Dashboards"
		unzip beats-dashboards-*.zip

		printLineBetweenCode "Load Dashboards"
		cd beats-dashboards-*
    		./load.sh
		cd /home/martijn-master/Desktop/


	printStartEnd "end" "Load Kibana Dashboard"
else
	printf "${warningColor}[WARNING!]: Load Kibana Dashboard wordt niet geinstalleerd${NC}\n"
fi
#LOADKIBANADASH============================================================================
#LOADFILEBEATINELASTIC=====================================================================
if [ $ExecuteLoadFileBeatElastic == "true" ]; then
	printStartEnd "start" "Load File Beat Elastic"

		printLineBetweenCode "Download filebeat template"
		cd ~
    		curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json

		printLineBetweenCode "Load template"
		curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json

	printStartEnd "end" "Load File Beat Elastic"
else
	printf "${warningColor}[WARNING!]: Load File Beat Elastic wordt niet geinstalleerd${NC}\n"
fi
#LOADFILEBEATINELASTIC=====================================================================
#SETUPFILEBEAT=============================================================================
if [ $ExecuteSetupFileBeat == "true" ]; then
	printStartEnd "start" "Setup FileBeat"

		printLineBetweenCode "Opnieuw Alle keys accepteren"
		yes | sudo salt-key --accept-all

		printLineBetweenCode "Opnieuw Overzicht alle keys"
		sudo salt-key --list all

		printLineBetweenCode "Install openssh on Minion"
		sudo salt '*' cmd.run 'cd /home/martijn-master/Desktop/; yes | sudo apt-get install openssh-server; sudo service ssh restart'

		#Sleep om ssh werkent te krijgen op de minion
		sleepForXSeconds 3

		printLineBetweenCode "Certificaat van de Master overzetten naar Minion"
		printf "${notifyColor}[LETOP!]: ========================================================================${NC}\n"
		printf "${notifyColor}[LETOP!]: Vul hier het wactwoord in van de minion om het certificaat te versturen!${NC}\n"
		printf "${notifyColor}[LETOP!]: vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv${NC}\n"
		scp /etc/pki/tls/certs/logstash-forwarder.crt martijn-master@$minionIP:/tmp

		printLineBetweenCode "certificaat op de goeie plek zetten"
		sudo salt '*' cmd.run '	sudo mkdir -p /etc/pki/tls/certs; 
					sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/'

		printLineBetweenCode "Downloaden fileBeat + key op Minion"
		sudo salt '*' cmd.run '	echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee -a /etc/apt/sources.list.d/beats.list;
					wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -'

		printLineBetweenCode "Installeren fileBeat op Minion"
		sudo salt '*' cmd.run '	sudo apt-get update;
					yes | sudo apt-get install filebeat' 

		printLineBetweenCode "Configuratie aanpassen"
		sudo salt '*' cmd.script "salt://changeConfigFileBeat.sh"

	printStartEnd "end" "Setup FileBeat"
else
	printf "${warningColor}[WARNING!]: Setup FileBeat wordt niet geinstalleerd${NC}\n"
fi
#SETUPFILEBEAT=============================================================================
#KUBERNETES================================================================================
if [ $ExecuteKubernetes == "true" ]; then
	printStartEnd "start" "Kubernetes"

		printLineBetweenCode "START"
		echo "martijnmaster-VirtualBox ALL = NOPASSWD: /bin/chown, /bin/cp" >> /etc/sudoers

		printLineBetweenCode "Install"
		apt-get update && apt-get install -y apt-transport-https curl
		curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -

		printLineBetweenCode "EOF"
cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb https://apt.kubernetes.io/ kubernetes-xenial main
EOF

		printLineBetweenCode "Update"
		apt-get update
		apt-get install -y kubelet kubeadm kubectl
		apt-mark hold kubelet kubeadm kubectl

		printLineBetweenCode "swap"
		sudo swapoff -a

		printLineBetweenCode "sed"
		sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
	
		printLineBetweenCode "advertise"
		kubeadm init
	
		printLineBetweenCode "Make Dir .kube"
		su martijnmaster-VirtualBox -c 'mkdir -p $HOME/.kube'

		printLineBetweenCode "Copy config"
		su martijnmaster-VirtualBox -c 'sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config'
		su martijnmaster-VirtualBox -c 'sudo chown $(id -u):$(id -g) $HOME/.kube/config'
	
		printLineBetweenCode "ExportKubeConfig"
		export KUBECONFIG=/etc/kubernetes/admin.conf

		printLineBetweenCode "Weave Apply"
		kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"

		printLineBetweenCode "Genereate Key"
		openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | \
	   	openssl dgst -sha256 -hex | sed 's/^.* //'
		
	printStartEnd "end" "Docker Compose"
else
	printf "${warningColor}[WARNING!]: KUBERNETES wordt niet geinstalleerd${NC}\n"
fi
#KUBERNETES=============================================================================
