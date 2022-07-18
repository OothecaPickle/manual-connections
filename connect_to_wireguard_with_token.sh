#!/usr/bin/env bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This function allows you to check if the required tools have been installed.
check_tool() {
  cmd=$1
  if ! command -v "$cmd" >/dev/null; then
    echo "$cmd could not be found"
    echo "Please install $cmd"
    exit 1
  fi
}
# Now we call the function to make sure we can use wg-quick, curl and jq.
check_tool wg-quick
check_tool curl
check_tool jq

# Check if terminal allows output, if yes, define colors for output
if [[ -t 1 ]]; then
  ncolors=$(tput colors)
  if [[ -n $ncolors && $ncolors -ge 8 ]]; then
    red=$(tput setaf 1) # ANSI red
    green=$(tput setaf 2) # ANSI green
    nc=$(tput sgr0) # No Color
  else
    red=''
    green=''
    nc='' # No Color
  fi
fi

# PIA currently does not support IPv6. In order to be sure your VPN
# connection does not leak, it is best to disabled IPv6 altogether.
# IPv6 can also be disabled via kernel commandline param, so we must
# first check if this is the case.
if [[ -f /proc/net/if_inet6 ]] &&
  [[ $(sysctl -n net.ipv6.conf.all.disable_ipv6) -ne 1 ||
     $(sysctl -n net.ipv6.conf.default.disable_ipv6) -ne 1 ]]
then
  echo -e "${red}You should consider disabling IPv6 by running:"
  echo "sysctl -w net.ipv6.conf.all.disable_ipv6=1"
  echo -e "sysctl -w net.ipv6.conf.default.disable_ipv6=1${nc}"
fi

# Check if the mandatory environment variables are set.
if [[ -z $WG_SERVER_IP ||
      -z $PIA_TOKEN ]]; then
  echo -e "${red}This script requires 2 env vars:"
  echo "WG_SERVER_IP - IP that you want to connect to"
  echo "PIA_TOKEN    - your authentication token"
  echo
  echo "You can also specify optional env vars:"
  echo "PIA_PF                - enable port forwarding"
  echo "PAYLOAD_AND_SIGNATURE - In case you already have a port."
  echo
  echo "An easy solution is to just run get_region_and_token.sh"
  echo "as it will guide you through getting the best server and"
  echo "also a token. Detailed information can be found here:"
  echo -e "https://github.com/pia-foss/manual-connections${nc}"
  exit 1
fi

# Create ephemeral wireguard keys, that we don't need to save to disk.
privKey=$(wg genkey)
export privKey
pubKey=$( echo "$privKey" | wg pubkey)
export pubKey

# Authenticate via the PIA WireGuard RESTful API.
# This will return a JSON with data required for authentication.
# The certificate is required to verify the identity of the VPN server.
# In case you didn't clone the entire repo, get the certificate from:
# https://github.com/pia-foss/manual-connections/blob/master/ca.rsa.4096.crt
# In case you want to troubleshoot the script, replace -s with -v.
echo "Trying to connect to the PIA WireGuard API on $WG_SERVER_IP..."
wireguard_json="$(curl -Gks \
  --data-urlencode "pt=${PIA_TOKEN}" \
  --data-urlencode "pubkey=$pubKey" \
  "https://${WG_SERVER_IP}:1337/addKey" )"
export wireguard_json

# Check if the API returned OK and stop this script if it didn't.
if [[ $(echo "$wireguard_json" | jq -r '.status') != "OK" ]]; then
  >&2 echo -e "${red}Server did not return OK. Stopping now.${nc}"
  exit 1
fi

# Multi-hop is out of the scope of this repo, but you should be able to
# get multi-hop running with both WireGuard and OpenVPN by playing with
# these scripts. Feel free to fork the project and test it out.
echo
echo "Trying to disable a PIA WG connection in case it exists..."
wg-quick down pia && echo -e "${green}\nPIA WG connection disabled!${nc}"
echo

# Create the WireGuard config based on the JSON received from the API
# In case you want this section to also add the DNS setting, please
# start the script with PIA_DNS=true.
# This uses a PersistentKeepalive of 25 seconds to keep the NAT active
# on firewalls. You can remove that line if your network does not
# require it.
#if [[ $PIA_DNS == "true" ]]; then
#  dnsServer=$(echo "$wireguard_json" | jq -r '.dns_servers[0]')
#  echo "Trying to set up DNS to $dnsServer. In case you do not have resolvconf,"
#  echo "this operation will fail and you will not get a VPN. If you have issues,"
#  echo "start this script without PIA_DNS."
#  echo
#  dnsSettingForVPN="DNS = $dnsServer"
#fi
#echo -n "Trying to write /etc/wireguard/pia.conf..."
#mkdir -p /etc/wireguard
echo -n "Trying to write /usr/local/etc/wireguard/pia.conf..."
echo "
[Interface]
Address = $(echo "$wireguard_json" | jq -r '.peer_ip')
PrivateKey = $privKey
PostUp = sudo killswitch -e
PostDown = sudo killswitch -d
[Peer]
PersistentKeepalive = 25
PublicKey = $(echo "$wireguard_json" | jq -r '.server_key')
AllowedIPs = 0.0.0.0/2,64.0.0.0/3,96.0.0.0/4,112.0.0.0/5,120.0.0.0/6,124.0.0.0/7,126.0.0.0/8,128.0.0.0/3,160.0.0.0/5,168.0.0.0/8,169.0.0.0/9,169.128.0.0/10,169.192.0.0/11,169.224.0.0/12,169.240.0.0/13,169.248.0.0/14,169.252.0.0/15,169.255.0.0/16,170.0.0.0/7,172.0.0.0/12,172.32.0.0/11,172.64.0.0/10,172.128.0.0/9,173.0.0.0/8,174.0.0.0/7,176.0.0.0/4,192.0.0.0/9,192.128.0.0/11,192.160.0.0/13,192.169.0.0/16,192.170.0.0/15,192.172.0.0/14,192.176.0.0/12,192.192.0.0/10,193.0.0.0/8,194.0.0.0/7,196.0.0.0/6,200.0.0.0/5,208.0.0.0/4,240.0.0.0/5,248.0.0.0/6,252.0.0.0/7,254.0.0.0/8,255.0.0.0/9,255.128.0.0/10,255.192.0.0/11,255.224.0.0/12,255.240.0.0/13,255.248.0.0/14,255.252.0.0/15,255.254.0.0/16,255.255.0.0/17,255.255.128.0/18,255.255.192.0/19,255.255.224.0/20,255.255.240.0/21,255.255.248.0/22,255.255.252.0/23,255.255.254.0/24,255.255.255.0/25,255.255.255.128/26,255.255.255.192/27,255.255.255.224/28,255.255.255.240/29,255.255.255.248/30,255.255.255.252/31,255.255.255.254/32
Endpoint = ${WG_SERVER_IP}:$(echo "$wireguard_json" | jq -r '.server_port')
" > /usr/local/etc/wireguard/pia.conf || exit 1
echo -e "${green}OK!${nc}"

# Start the WireGuard interface.
# If something failed, stop this script.
# If you get DNS errors because you miss some packages,
# just hardcode /etc/resolv.conf to "nameserver 10.0.0.242".
echo
echo "Trying to create the wireguard interface..."
sudo -E AUTO_ROUTE4=1 wg-quick up pia || exit 1
echo
echo -e "${green}The WireGuard interface got created.${nc}

At this point, internet should work via VPN.

To disconnect the VPN, run:

--> ${green}wg-quick down pia${nc} <--
"

# This section will stop the script if PIA_PF is not set to "true".
if [[ $PIA_PF != "true" ]]; then
  echo "If you want to also enable port forwarding, you can start the script:"
  echo -e "$ ${green}USINGWG=TRUE" \
    "PF_GATEWAY=$(echo "$wireguard_json" | jq -r '.server_vip')" \
    "pia-port-forward${nc}"
  echo -en "USINGWG=TRUE" \
    "PF_GATEWAY=$(echo "$wireguard_json" | jq -r '.server_vip')" \
    "pia-port-forward" | pbcopy
  echo
  echo "The location used must be port forwarding enabled, or this will fail."
  echo "Calling the ./get_region script with PIA_PF=true will provide a filtered list."
  exit 1
fi

echo -ne "This script got started with ${green}PIA_PF=true${nc}.

Starting port forwarding in "
for i in {5..1}; do
  echo -n "$i..."
  sleep 1
done
echo
echo

echo -e "Starting procedure to enable port forwarding by running the following command:
$ ${green}USINGWG=TRUE \\
  PF_GATEWAY=$(echo "$wireguard_json" | jq -r '.server_vip') \\
  ./port_forwarding.sh${nc}"

USINGWG=TRUE \
  PF_GATEWAY=$(echo "$wireguard_json" | jq -r '.server_vip') \
  ./port_forwarding.sh
