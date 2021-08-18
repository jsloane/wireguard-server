#!/bin/bash

cp /etc/wireguard/template-post-up.sh /etc/wireguard/post-up.sh
cp /etc/wireguard/template-post-down.sh /etc/wireguard/post-down.sh

sed -i "s#internet_ip#$1#" /etc/wireguard/post-up.sh
sed -i "s#internet_ip#$1#" /etc/wireguard/post-down.sh

chmod ugo+x /etc/wireguard/post-up.sh
chmod ugo+x /etc/wireguard/post-down.sh
