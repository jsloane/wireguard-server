#!/bin/bash

# Display usage
display_usage() {
	cat <<EOF
Usage: $0 [DDNS_TOKEN] [DDNS_DOMAINS]

-h| --help                         This script is used to install and configure duck ddns.

DDNS_TOKEN                         DuckDNS token
DDNS_DOMAINS                       DuckDNS domains

Example usage:
sudo ~/wireguard-server/install-ddns.sh duckdns-token duckdns-domain

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

set -e # exit when any command fails

echo
echo "#################################"
echo "### Running ddns setup script ###"
echo "#################################"

SCRIPT_DIR=$(dirname $(realpath $0))
DDNS_TOKEN="$1"
DDNS_DOMAINS="$2"

echo ""
echo "##### Parameters #####"
echo "SCRIPT_DIR =                   $SCRIPT_DIR"
echo "DDNS_TOKEN =                   $DDNS_TOKEN"
echo "DDNS_DOMAINS =                 $DDNS_DOMAINS"
echo ""


###############
# Duck DNS
###############

cp $SCRIPT_DIR/scripts/ip-address-update /etc/cron.hourly/ip-address-update
sed -i "s#token_value#$DDNS_TOKEN#" /etc/cron.hourly/ip-address-update
sed -i "s#domains_value#$DDNS_DOMAINS#" /etc/cron.hourly/ip-address-update
chmod ugo+x /etc/cron.hourly/ip-address-update
