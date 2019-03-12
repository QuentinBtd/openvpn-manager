#!/bin/bash
#
# https://github.com/QuentinBtd/openvpn-manager/
# Based on https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2019 Nyr. Released under the MIT License.
#


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available
You need to enable TUN before running this script"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	exit
fi

IPprefix_by_netmask() {
    #function returns prefix for given netmask in arg1
    bits=0
    for octet in $(echo $1| sed 's/\./ /g'); do 
         binbits=$(echo "obase=2; ibase=10; ${octet}"| bc | sed 's/0//g') 
         let bits+=${#binbits}
    done
    echo "${bits}"
}

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/servers/$SERVER/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/servers/$SERVER/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/servers/$SERVER/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/servers/$SERVER/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/servers/$SERVER/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

newserver () {
	cd /etc/openvpn/
	cp -R server-template servers/$1
	cd servers/$1/easy-rsa/ 
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/servers/$1
	chown nobody:$GROUPNAME /etc/openvpn/servers/$1/crl.pem
	openvpn --genkey --secret /etc/openvpn/servers/$1/ta.key
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/servers/$1/dh.pem

	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP address: " -e -i $IP IP
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		read -p "Public IP address / hostname: " -e PUBLICIP
	fi
	echo
	echo "Which protocol do you want for OpenVPN connections?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "What port do you want OpenVPN listening to?"
	read -p "Port: " -e -i 1194 PORT
	echo
	echo "Which DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Which internal network address do you want for OpenVPN ?"
	echo "Example : 10.8.0.0, 192.168.0.0..."
	read -p "Internal network address: " -e NETWORK
	while ! echo "$NETWORK" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; do
		echo "Bad network address !"
		read -p "Please enter a valid internal network address: " -e NETWORK
	done
	if echo "$NETWORK" | grep -qE '^(10\.)'; then
		SUGGEST="255."	
	elif echo "$NETWORK" | grep -qE '^(172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)'; then
		SUGGEST="255.240."	
	elif echo "$NETWORK" | grep -qE '^(192\.168)'; then
		SUGGEST="255.255."
	fi
	echo "Which subnet mask do you want for your OpenVPN internal network ?"
	read -p "Subnet mask: " -e -i "$SUGGEST" NETMASK
	while ! echo "$NETMASK" | grep -qE '^(254|252|248|240|224|192|128)\.0\.0\.0|255\.(254|252|248|240|224|192|128|0)\.0\.0|255\.255\.(254|252|248|240|224|192|128|0)\.0|255\.255\.255\.(254|252|248|240|224|192|128|0)'; do
		echo "Bad subnet mask !"
		read -p "Please enter a valid internal subnet mask: " -e -i "$SUGGEST" NETMASK
	done
	NETMASKCIDR=$(IPprefix_by_netmask $NETMASK)
		
	### FAIRE CHECK DU MASK 
	

	
	# Generate server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca /etc/openvpn/servers/$1/ca.crt
cert /etc/openvpn/servers/$1/server.crt
key /etc/openvpn/servers/$1/server.key
dh /etc/openvpn/servers/$1/dh.pem
auth SHA512
tls-auth /etc/openvpn/servers/$1/ta.key 0
topology subnet
server $NETWORK $NETMASK
ifconfig-pool-persist /etc/openvpn/servers/$1/ipp.txt" > /etc/openvpn/servers/$1/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/servers/$1/server.conf
	# DNS
	case $DNS in
		1)
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/servers/$1/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/servers/$1/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/servers/$1/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/servers/$1/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/servers/$1/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/servers/$1/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/servers/$1/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/servers/$1/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify /etc/openvpn/servers/$1/crl.pem" >> /etc/openvpn/servers/$1/server.conf
	ln -s /etc/openvpn/servers/$1/server.conf /etc/openvpn/$SERVER.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=$NETWORK/$NETMASKCIDR
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=$NETWORK/$NETMASKCIDR
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP
	else
		# Needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# Set NAT for the VPN subnet
		iptables -t nat -A POSTROUTING -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s $NETWORK/$NETMASKCIDR -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s $NETWORK/$NETMASKCIDR -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			yum install policycoreutils-python -y
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@$SERVER.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@$SERVER.service
			systemctl enable openvpn@$SERVER.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# If the server is behind a NAT, use the correct IP address
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi	
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/servers/$1/client-common.txt
}

function installopenvpn () {
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates -y
	fi
	cd /etc/openvpn/
	rm -Rf /etc/openvpn/*
	mkdir server-template
	mkdir servers
	cd server-template/
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.5/EasyRSA-nix-3.0.5.tgz'
	wget -O easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo easyrsa.tgz "$EASYRSAURL"
	tar xzf easyrsa.tgz 
	mv EasyRSA-3.0.5/ easy-rsa/
	rm -f easyrsa.tgz
}

function delete-iptables-rules () {
	PORT=$(grep '^port ' /etc/openvpn/servers/$1/server.conf | cut -d " " -f 2)
	PROTOCOL=$(grep '^proto ' /etc/openvpn/servers/$1/server.conf | cut -d " " -f 2)
	NETWORK=$(grep '^server ' /etc/openvpn/servers/$1/server.conf | cut -d " " -f 2)
	NETMASK=$(grep '^server ' /etc/openvpn/servers/$1/server.conf | cut -d " " -f 3)
	NETMASKCIDR=$(IPprefix_by_netmask $NETMASK)
	if pgrep firewalld; then
		IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s $NETWORK/$NETMASKCIDR '"'"'!'"'"' -d $NETWORK/$NETMASKCIDR -j SNAT --to ' | cut -d " " -f 10)
		# Using both permanent and not permanent rules to avoid a firewalld reload.
		firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --remove-source=$NETWORK/$NETMASKCIDR
		firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --remove-source=$NETWORK/$NETMASKCIDR
		firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP
		firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP
	else
#		IP=$(grep 'iptables -t nat -A POSTROUTING -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
		IP=$(iptables -t nat -L | grep "$NETWORK/$NETMASKCIDR" | grep -o -e "to:[0-9.]*" | grep -o -e "[0-9.]*")
		iptables -t nat -D POSTROUTING -s $NETWORK/$NETMASKCIDR ! -d $NETWORK/$NETMASKCIDR -j SNAT --to $IP
		sed -i '/iptables -t nat -A POSTROUTING -s $NETWORK\/$NETMASKCIDR ! -d $NETWORK\/$NETMASKCIDR -j SNAT --to /d' $RCLOCAL
		if iptables -L -n | grep -qE '^ACCEPT'; then
			iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -D FORWARD -s $NETWORK/$NETMASKCIDR -j ACCEPT
			iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
			sed -i "/iptables -I FORWARD -s $NETWORK\/$NETMASKCIDR -j ACCEPT/d" $RCLOCAL
			sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
		fi
	fi
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
	fi
}

if [[ "$OS" = 'debian' ]]; then
		if [[ $(dpkg --list | grep 'openvpn') ]]; then
			INSTALLED="1"
		fi
else
	if [[ $(yum list installed | grep 'openvpn') ]]; then
		INSTALLED="1"
	fi
fi

if [[ $INSTALLED ]]; then
	while :
	do
		echo "Looks like OpenVPN is already installed."
		echo
		echo "What do you want to do?"
		echo "   1) Add a new server"
		echo "   2) Manage a existing server"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo
			echo "Tell me a name for the server."
			read -p "Server name: " -e -i "server-" SERVER
			newserver $SERVER
			;;
			2)
			echo
			echo "Select the server to manager:"
			ls /etc/openvpn/servers/
			read -p "Select a server: " SERVER
			while :
			do
				echo "Looks like OpenVPN is already installed."
				echo
				echo "What do you want to do?"
				echo "   1) Add a new user"
				echo "   2) Revoke an existing user"
				echo "   3) Delete this server"
				echo "   4) Exit"
				read -p "Select an option [1-4]: " option
				case $option in
					1) 
					echo
					echo "Tell me a name for the client certificate."
					echo "Please, use one word only, no special characters."
					read -p "Client name: " -e CLIENT
					cd /etc/openvpn/servers/$SERVER/easy-rsa/
					EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
					# Generates the custom client.ovpn
					newclient "$CLIENT"
					echo
					echo "Client $CLIENT added, configuration is available at:" ~/"$CLIENT.ovpn"
					exit
					;;
					2)
					# This option could be documented a bit better and maybe even be simplified
					# ...but what can I say, I want some sleep too
					NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/servers/$SERVER/easy-rsa/pki/index.txt | grep -c "^V")
					if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
						echo
						echo "You have no existing clients!"
						exit
					fi
					echo
					echo "Select the existing client certificate you want to revoke:"
					tail -n +2 /etc/openvpn/servers/$SERVER/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
					if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
						read -p "Select one client [1]: " CLIENTNUMBER
					else
						read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
					fi
					CLIENT=$(tail -n +2 /etc/openvpn/servers/$SERVER/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
					echo
					read -p "Do you really want to revoke access for client $CLIENT? [y/N]: " -e REVOKE
					if [[ "$REVOKE" = 'y' || "$REVOKE" = 'Y' ]]; then
						cd /etc/openvpn/servers/$SERVER/easy-rsa/
						./easyrsa --batch revoke $CLIENT
						EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
						rm -f pki/reqs/$CLIENT.req
						rm -f pki/private/$CLIENT.key
						rm -f pki/issued/$CLIENT.crt
						rm -f /etc/openvpn/servers/$SERVER/crl.pem
						cp /etc/openvpn/servers/$SERVER/easy-rsa/pki/crl.pem /etc/openvpn/servers/$SERVER/crl.pem
						# CRL is read with each client connection, when OpenVPN is dropped to nobody
						chown nobody:$GROUPNAME /etc/openvpn/servers/$SERVER/crl.pem
						systemctl reload openvpn@$SERVER.service
						echo
						echo "Certificate for client $CLIENT revoked!"
					else
						echo
						echo "Certificate revocation for client $CLIENT aborted!"
					fi
					exit
					;;
					3)
					read -p "Do you really want to remove this server ($SERVER)? [y/N]: " -e REMOVE
					if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
						systemctl stop openvpn@$SERVER.service
						delete-iptables-rules $SERVER
						cd /etc/openvpn/
						rm $SERVER.conf
						cd servers/
						rm -Rf $SERVER
						systemctl reset-failed
						echo
						echo "Server $SERVER removed !"
						exit
					else
						echo
						echo "Removal aborted!"
					fi
					;;
					4)
					exit
					;;
				esac
			done
			;;
			3) 
			echo
			read -p "Do you really want to remove OpenVPN? [y/N]: " -e REMOVE
			if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
				cd /etc/openvpn/servers/
				for DIR in */ ;
				do
					delete-iptables-rules $DIR
				done
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				systemctl reset-failed
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "Removal aborted!"
			fi
			exit
			;;
			4)
			exit
			;;
		esac	
	done
else
	installopenvpn
fi
