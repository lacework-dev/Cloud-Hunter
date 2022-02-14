#!/bin/bash

# Greynoise IP Huntor
# Lacework Labs
# v0.1 - February 2022
# greg.foss@lacework.net
#
# Use alongside cloud-hunter.py to evaluate IP's with Greynoise
#
# EDIT THE CONFIGURATION FILE TO UPDATE SCRIPT OPTIONS
# ==============================
configuration_file="./config.json"
# ==============================

cloud_hunter=$(cat $configuration_file | jq ."cloud_hunter_script_location" | tr -d '"')
gn_api_key=$(cat $configuration_file | jq ."greynoise_api_key" | tr -d '"')
gn_folder=$(echo $configuration_file | sed 's/\/config.json//g')

CYAN='\033[0;36m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

banner="""
   /^^^^   
 /^    /^^ 
/^^            Greynoise
/^^            IP-Hunter
/^^   /^^^^
 /^^    /^ 
  /^^^^^   
          Lacework Labs
"""

while getopts i:t:e: flag
do
	case "${flag}" in
		i) ipaddress=${OPTARG};;
		t) timestamp=${OPTARG};;
		e) environment=${OPTARG};;
	esac
done
sp="/-\|"
sc=0
spin() {
   printf "\b${sp:sc++:1}"
   ((sc==${#sp})) && sc=0
}
endspin() {
   printf "\r%s\n" "$@"
}
if [[ $1 == $null ]]; then
	echo -e "${BLUE}$banner${NC}"
	echo -e "=========================[ ${GREEN}HELP${NC} ]========================="
	echo -e "${CYAN}Hunt via IP Address:${NC}"
	echo "$ ./greynoise-hunt.sh -i \"ip address\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo -e "${RED} [ ! ] IP Address is required"
	echo -e " [ - ] Timeframe and Environment are optional${NC}"
	echo "============================================================"
	echo 
elif [[ $ipaddress != $null ]]; then
	if [[ $ipaddress == 'exists' ]]; then
		echo -e "${RED} [ ! ] Checking all IP's - this may take a long time..."
		echo -e " [ ! ] Results are limited to the most recent 5000 hits${NC}"
		echo 
	fi
	if [[ $timestamp != $null ]]; then
		if [[ $environment != $null ]]; then
			ip_hits=$($cloud_hunter -ip $ipaddress -j -t $timestamp -environment $environment)
		else
			ip_hits=$($cloud_hunter -ip $ipaddress -j -t $timestamp)
		fi
	else
		if [[ $environment != $null ]]; then
			ip_hits=$($cloud_hunter -ip $ipaddress -j -environment $environment)
		else
			ip_hits=$($cloud_hunter -ip $ipaddress -j)
		fi
	fi
	ip_count=$(echo $ip_hits | jq '. | length')
	echo -e "${CYAN}$ip_count${NC} - Total IP's found"
	for i in $(seq 0 $ip_count); do
		spin
		echo $ip_hits | jq .\[$i\].EVENT.sourceIPAddress >> tmp.tmp
	done
	endspin
	cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > ips.tmp
	rm tmp.tmp
	sed -i "" '/^[[:space:]]*$/d' ips.tmp
	unique_ip_count=$(cat ips.tmp | wc -l | sed 's/ //g')
	echo -e "${CYAN}$unique_ip_count${NC} - Unique IP's that will be analyzed"
	if [[ $environment != $null ]]; then
		$gn_folder/scripts/greynoise-ip.py -f ips.tmp -o $environment-ips.csv -k $gn_api_key
	else
		$gn_folder/scripts/greynoise-ip.py -f ips.tmp -k $gn_api_key
	fi
	rm ips.tmp
fi
unset ipaddress
unset timestamp
unset environment