#!/bin/bash

### Ubuntu client setup
# sudo apt install wireguard
# sudo nano /etc/wireguard/wg0.conf
# sudo systemctl enable wg-quick@wg0.service
# sudo systemctl start wg-quick@wg0.service

### testing network connectivity
## on destination server:
# nc -lu udpport
# nc -l tcpport
## on external client:
# echo Test message | nc -4u -w1 hostname udpport
# echo Test message | nc -4 -w1 hostname tcpport

# Reference https://reposhub.com/python/security/mochman-Bypass_CGNAT.html
# Note Oracle Cloud firewall documentation https://docs.oracle.com/en-us/iaas/Content/Compute/References/bestpracticescompute.htm


# Display usage
display_usage() {
	cat <<EOF
Usage: $0 DDNS_TOKEN DDNS_DOMAINS WG_SERVER_HOSTNAME WG_SERVER_PORT PORT_FORWARDING_DESTINATIONS

-h| --help                         This script is used to install, configure and run a WireGuard server with port forwarding to the client.
                                   Re-running this script will replace previous configuration.

DDNS_TOKEN                         DuckDNS token
DDNS_DOMAINS                       DuckDNS domains
WG_SERVER_HOSTNAME                 The hostname of the WireGuard Server
WG_SERVER_PORT                     The port of the WireGuard Server
PORT_FORWARDING_DESTINATIONS       The protocol and ports you wish to forward to the WireGuard Client, in format port/protocol/IP.
                                   Multiple entries are supported when separated by a comma.
                                   Eg: 80/tcp/192.168.1.10

This script must be run with super-user privileges.
EOF
}
if [[ ( $1 == "--help") || $1 == "-h" || $# == 0 ]]; then
	display_usage
	exit 0
fi # display error if the script is not run as root user 
if [[ "$EUID" -ne 0 ]]; then
	echo "This script must be run with super-user privileges."
	exit 1
fi


echo
echo "###################################"
echo "### Running server setup script ###"
echo "###################################"

SCRIPT_DIR=$(dirname $(realpath $0))
DDNS_TOKEN="$1"
DDNS_DOMAINS="$2"
WG_SERVER_HOSTNAME="$3"
WG_SERVER_PORT="$4"
PORT_FORWARDING_DESTINATIONS="$5"
SSHD_PORT=22
WG_CLIENT_IP=10.200.200.2
INTERNET_INF=$(ip -o -4 route show to default | awk '{print $5}')

echo ""
echo "##### Parameters #####"
echo "SCRIPT_DIR =                   $SCRIPT_DIR"
echo "DDNS_TOKEN =                   $DDNS_TOKEN"
echo "DDNS_DOMAINS =                 $DDNS_DOMAINS"
echo "INTERNET_INF =                 $INTERNET_INF"
echo "SSHD_PORT =                    $SSHD_PORT"
echo "WG_SERVER_HOSTNAME =           $WG_SERVER_HOSTNAME"
echo "WG_SERVER_PORT =               $WG_SERVER_PORT"
echo "WG_CLIENT_IP =                 $WG_CLIENT_IP"
echo "PORT_FORWARDING_DESTINATIONS = $PORT_FORWARDING_DESTINATIONS"
echo ""


###############
# Duck DNS
###############

cp $SCRIPT_DIR/scripts/ip-address-update /etc/cron.hourly/ip-address-update
sed -i "s#token_value#$DDNS_TOKEN#" /etc/cron.hourly/ip-address-update
sed -i "s#domains_value#$DDNS_DOMAINS#" /etc/cron.hourly/ip-address-update
chmod ugo+x /etc/cron.hourly/ip-address-update


###############
# WireGuard server
###############

### WireGuard Server setup

if ! [ -x "$(command -v wg)" ]; then
	# accept all incoming traffic # TODO avoid removing oracle iptables rules
	if [ ! -f "~/rules.v4.backup" ]; then
		echo "Backing up /etc/iptables/rules.v4..."
		cp /etc/iptables/rules.v4 ~/rules.v4.backup
	fi
	echo "Reconfiguring firewall..."
	iptables --flush
	netfilter-persistent save
	netfilter-persistent reload
	iptables -S

	echo "WireGuard not found, updating packages and installing..."
	apt update
	apt install -y wireguard

	echo "Enabling packet forwarding..."
	tee -a /etc/sysctl.conf > /dev/null <<EOT
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOT
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1
	/etc/init.d/procps restart
fi

# stop if already installed and running
if systemctl is-active --quiet wg-quick@wg0.service; then
	echo "WireGuard service running, stopping..."
	systemctl stop wg-quick@wg0.service
fi

INTERNET_IP=`dig @resolver4.opendns.com myip.opendns.com +short`
echo "INTERNET_IP =                  $INTERNET_IP"

if [ ! -f "/etc/wireguard/server_public_key" ]; then
    echo "Generating server keys..."
	bash -c 'umask 077; wg genkey | tee /etc/wireguard/server_private_key | wg pubkey > /etc/wireguard/server_public_key'
fi

if [ ! -f "/etc/wireguard/client_01_public_key" ]; then
    echo "Generating client keys..."
	bash -c 'umask 077; wg genkey | tee /etc/wireguard/client_01_private_key | wg pubkey > /etc/wireguard/client_01_public_key'
fi

# create PostUp and PostDown script files
tee /etc/wireguard/template-post-up.sh > /dev/null <<EOT
#!/bin/bash

# Generic traffic
iptables -A FORWARD -i \$1 -j ACCEPT
iptables -A FORWARD -o \$1 -j ACCEPT
iptables -t nat -A POSTROUTING -o $INTERNET_INF -j MASQUERADE

# Forward traffic on all tcp/udp ports except ports used for SSH and WireGuard Server
iptables -t nat -A PREROUTING -p tcp -i $INTERNET_INF '!' --dport 22 -j DNAT --to-destination $WG_CLIENT_IP
iptables -t nat -A POSTROUTING -o $INTERNET_INF -j SNAT --to-source internet_ip
iptables -t nat -A PREROUTING -p udp -i $INTERNET_INF '!' --dport $WG_SERVER_PORT -j DNAT --to-destination $WG_CLIENT_IP

EOT

tee /etc/wireguard/template-post-down.sh > /dev/null <<EOT
#!/bin/bash

# Generic traffic
iptables -D FORWARD -i \$1 -j ACCEPT
iptables -D FORWARD -o \$1 -j ACCEPT
iptables -t nat -D POSTROUTING -o $INTERNET_INF -j MASQUERADE

# Forward traffic on all tcp/udp ports except ports used for SSH and WireGuard Server
iptables -t nat -D PREROUTING -p tcp -i $INTERNET_INF '!' --dport 22 -j DNAT --to-destination $WG_CLIENT_IP
iptables -t nat -D POSTROUTING -o $INTERNET_INF -j SNAT --to-source internet_ip
iptables -t nat -D PREROUTING -p udp -i $INTERNET_INF '!' --dport $WG_SERVER_PORT -j DNAT --to-destination $WG_CLIENT_IP;

EOT

cp $SCRIPT_DIR/scripts/write_wireguard_postup_postdown.sh /etc/wireguard/write_wireguard_postup_postdown.sh
chmod ugo+x /etc/wireguard/write_wireguard_postup_postdown.sh
/etc/wireguard/write_wireguard_postup_postdown.sh $INTERNET_IP

# create server config file
bash -c 'umask 077; touch /etc/wireguard/wg0.conf'

# write server details to server config file
tee /etc/wireguard/wg0.conf > /dev/null <<EOT
[Interface]
Address = 10.200.200.1/24
SaveConfig = true
PrivateKey = server_private_key
ListenPort = $WG_SERVER_PORT

# use scripts to manage dynamic external IP address
PostUp = /etc/wireguard/post-up.sh "%i"
PostDown = /etc/wireguard/post-down.sh "%i"

[Peer]
PublicKey = client_01_public_key
AllowedIPs = $WG_CLIENT_IP/32
EOT

# write server private key to config file
sed -i "s#server_private_key#$(cat /etc/wireguard/server_private_key)#" /etc/wireguard/wg0.conf

# write client public key to config file
sed -i "s#client_01_public_key#$(cat /etc/wireguard/client_01_public_key)#" /etc/wireguard/wg0.conf


### WireGuard Client setup

# Generate client PostUp and PostDown commands for port forwarding destinations
CLIENT_POSTUPDOWN=""
NEWLINE=$'\n'
for i in $(echo $PORT_FORWARDING_DESTINATIONS | sed "s/,/ /g")
do
	FORWARD_PORT=$(echo $i| cut -d'/' -f 1)
	FORWARD_PROTOCOL=$(echo $i| cut -d'/' -f 2)
	FORWARD_IP=$(echo $i| cut -d'/' -f 3)
	if [ ! -z $FORWARD_IP ]; then
		CLIENT_POSTUPDOWN+="PostUp = iptables -t nat -A PREROUTING -p $FORWARD_PROTOCOL --dport $FORWARD_PORT -j DNAT --to-destination $FORWARD_IP:$FORWARD_PORT; iptables -t nat -A POSTROUTING -p $FORWARD_PROTOCOL --dport $FORWARD_PORT -j MASQUERADE${NEWLINE}"
		CLIENT_POSTUPDOWN+="PostDown = iptables -t nat -D PREROUTING -p $FORWARD_PROTOCOL --dport $FORWARD_PORT -j DNAT --to-destination $FORWARD_IP:$FORWARD_PORT; iptables -t nat -D POSTROUTING -p $FORWARD_PROTOCOL --dport $FORWARD_PORT -j MASQUERADE${NEWLINE}"
	fi
	# TODO append to PostUp/PostDown scripts... if files exist
done

# create client config file
bash -c 'umask 077; touch /etc/wireguard/wg0-client-01.conf'

# write client config file
tee /etc/wireguard/wg0-client-01.conf > /dev/null <<EOT
[Interface]
Address = 10.200.200.2/32
PrivateKey = client_01_private_key
DNS = 1.1.1.1, 1.0.0.1

# if required, redirect port to another host. Packet forwarding will need to be enabled on client.
$CLIENT_POSTUPDOWN

[Peer]
PublicKey = server_public_key
# block untunneled traffic
AllowedIPs = 0.0.0.0/0
# allow untunneled traffic
#AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
Endpoint = $WG_SERVER_HOSTNAME:$WG_SERVER_PORT
PersistentKeepalive = 25
EOT

# write server public key to client config file
sed -i "s#server_public_key#$(cat /etc/wireguard/server_public_key)#" /etc/wireguard/wg0-client-01.conf

# write client private key to client config file
sed -i "s#client_01_private_key#$(cat /etc/wireguard/client_01_private_key)#" /etc/wireguard/wg0-client-01.conf


### setup server service
systemctl enable wg-quick@wg0.service
# start server service
systemctl start wg-quick@wg0.service

# check status
#systemctl status wg-quick@wg0.service
iptables -t nat -L -n -v
wg show

echo ""
echo "##################################"
echo "### Client configuration start ###"
echo "##################################"
cat /etc/wireguard/wg0-client-01.conf
echo "##################################"
echo "###  Client configuration end  ###"
echo "##################################"
echo ""
