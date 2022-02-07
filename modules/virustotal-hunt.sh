#!/bin/bash

# VirusTotal Indicator Huntor
# Lacework Labs
# v0.3 - February 2022
# greg.foss@lacework.net
#
# Use alongside cloud-hunter.py to evaluate Files, Domains, and IP's with VirusTotal
#
# EDIT THE CONFIGURATION FILE TO UPDATE SCRIPT OPTIONS
# ==============================
configuration_file="./config.json"
# ==============================

cloud_hunter=$(cat $configuration_file | jq ."cloud_hunter_script_location" | tr -d '"')
vt_api_key=$(cat $configuration_file | jq ."virustotal_api_key" | tr -d '"')
vt_folder=$(echo $configuration_file | sed 's/config.json//g')

CYAN='\033[0;36m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

banner="""
(             )
 \`--(_   _)--'
      Y-Y
     /@@ \\   Cloud-Hunter
    /     \\  >>---VT--->
    \`--'.  \             ,
        |   \`.__________/)
           Lacework Labs
"""

while getopts x:f:d:i:t:e: flag
do
	case "${flag}" in
		x) filetype=${OPTARG};;
		f) filename=${OPTARG};;
		d) domain=${OPTARG};;
		i) ipaddress=${OPTARG};;
		t) timestamp=${OPTARG};;
		e) environment=${OPTARG};;
	esac
done
if [[ $1 == $null ]]; then
	echo -e "${BLUE}$banner${NC}"
	echo -e "=========================[ ${GREEN}HELP${NC} ]========================="
	echo -e "${CYAN}Hunt via Filetype:${NC}"
	echo "$ ./virustotal-hunt.sh -x \"filetype\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo -e "${CYAN}Hunt via Filename, Extension, or Keyword:${NC}"
	echo "$ ./virustotal-hunt.sh -f \"filename\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo -e "${CYAN}Hunt via Domain:${NC}"
	echo "$ ./virustotal-hunt.sh -d \"domain\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo -e "${CYAN}Hunt via IP Address:${NC}"
	echo "$ ./virustotal-hunt.sh -i \"ip address\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo -e "${RED} [ ! ] Filename, Domain, or IP Address are required"
	echo -e " [ - ] Timeframe and Environment are optional${NC}"
	echo "============================================================"
	echo 
else
	echo

	# Filetype Hunting
	if [[ $filetype != $null ]]; then
		if [[ $filetype == 'exists' ]]; then
			echo -e "${RED} [ ! ] Checking all files - this may take a long time..."
			echo -e " [ ! ] Results are limited to the most recent 5000 hits${NC}"
			echo 
		fi
		if [[ $timestamp != $null ]]; then
			if [[ $environment != $null ]]; then
				filetype_hits=$($cloud_hunter -filetype $filetype -r -j -t $timestamp -environment $environment)
			else
				filetype_hits=$($cloud_hunter -filetype $filetype -r -j -t $timestamp)
			fi
		else
			if [[ $environment != $null ]]; then
				filetype_hits=$($cloud_hunter -filetype $filetype -r -j -environment $environment)
			else
				filetype_hits=$($cloud_hunter -filetype $filetype -r -j)
			fi
		fi
		filetype_count=$(echo $filetype_hits | jq '. | length')
		echo -e "${CYAN}$filetype_count${NC} - Total files found"
		for i in $(seq 0 $filetype_count); do
			echo $filetype_hits | jq .\[$i\].FILEDATA_HASH >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > hashes.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' hashes.tmp
		unique_filetype_count=$(cat hashes.tmp | wc -l | sed 's/ //g')
		echo -e "${CYAN}$unique_filetype_count${NC} - Unique files that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			$vt_folder/virustotal/vt-hash-check.py -f hashes.tmp -o $environment-hashes.csv -v $vt_api_key
		else
			$vt_folder/virustotal/vt-hash-check.py -f hashes.tmp -v $vt_api_key
		fi
		rm hashes.tmp

	# Filename Hunting
	elif [[ $filename != $null ]]; then
		if [[ $filename == 'exists' ]]; then
			echo -e "${RED} [ ! ] Checking all files - this may take a long time..."
			echo -e " [ ! ] Results are limited to the most recent 5000 hits${NC}"
			echo 
		fi
		if [[ $timestamp != $null ]]; then
			if [[ $environment != $null ]]; then
				file_hits=$($cloud_hunter -filename $filename -r -j -t $timestamp -environment $environment)
			else
				file_hits=$($cloud_hunter -filename $filename -r -j -t $timestamp)
			fi
		else
			if [[ $environment != $null ]]; then
				file_hits=$($cloud_hunter -filename $filename -r -j -environment $environment)
			else
				file_hits=$($cloud_hunter -filename $filename -r -j)
			fi
		fi
		file_count=$(echo $file_hits | jq '. | length')
		echo -e "${CYAN}$file_count${NC} - Total files found"
		for i in $(seq 0 $file_count); do
			echo $file_hits | jq .\[$i\].FILEDATA_HASH >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > hashes.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' hashes.tmp
		unique_file_count=$(cat hashes.tmp | wc -l | sed 's/ //g')
		echo -e "${CYAN}$unique_file_count${NC} - Unique files that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			$vt_folder/virustotal/vt-hash-check.py -f hashes.tmp -o $environment-hashes.csv -v $vt_api_key
		else
			$vt_folder/virustotal/vt-hash-check.py -f hashes.tmp -v $vt_api_key
		fi
		rm hashes.tmp
	
	# Domain Hunting
	elif [[ $domain != $null ]]; then
		if [[ $domain == 'exists' ]]; then
			echo -e "${RED} [ ! ] Checking all DNS queries - this may take a long time..."
			echo -e " [ ! ] Results are limited to the most recent 5000 hits${NC}"
			echo 
		fi
		if [[ $timestamp != $null ]]; then
			if [[ $environment != $null ]]; then
				dns_hits=$($cloud_hunter -dns $domain -r -j -t $timestamp -environment $environment)
			else
				dns_hits=$($cloud_hunter -dns $domain -r -j -t $timestamp)
			fi
		else
			if [[ $environment != $null ]]; then
				dns_hits=$($cloud_hunter -dns $domain -r -j -environment $environment)
			else
				dns_hits=$($cloud_hunter -dns $domain -r -j)
			fi
		fi
		dns_count=$(echo $dns_hits | jq '. | length')
		echo -e "${CYAN}$dns_count${NC} - Total Domains found"
		for i in $(seq 0 $dns_count); do
			echo $dns_hits | jq .\[$i\].HOSTNAME >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > dns.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' dns.tmp
		unique_dns_count=$(cat dns.tmp | wc -l | sed 's/ //g')
		echo -e "${CYAN}$unique_dns_count${NC} - Unique Domains that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			$vt_folder/virustotal/vt-dns-check.py -f dns.tmp -o $environment-dns.csv -v $vt_api_key
		else
			$vt_folder/virustotal/vt-dns-check.py -f dns.tmp -v $vt_api_key
		fi
		rm dns.tmp

	# IP Hunting
	elif [[ $ipaddress != $null ]]; then
		if [[ $ipaddress == 'exists' ]]; then
			echo -e "${RED} [ ! ] Checking all IP's - this may take a long time..."
			echo -e " [ ! ] Results are limited to the most recent 5000 hits${NC}"
			echo 
		fi
		if [[ $timestamp != $null ]]; then
			if [[ $environment != $null ]]; then
				ip_hits=$($cloud_hunter -ip $ipaddress -r -j -t $timestamp -environment $environment)
			else
				ip_hits=$($cloud_hunter -ip $ipaddress -r -j -t $timestamp)
			fi
		else
			if [[ $environment != $null ]]; then
				ip_hits=$($cloud_hunter -ip $ipaddress -r -j -environment $environment)
			else
				ip_hits=$($cloud_hunter -ip $ipaddress -r -j)
			fi
		fi
		ip_count=$(echo $ip_hits | jq '. | length')
		echo -e "${CYAN}$ip_count${NC} - Total IP's found"
		for i in $(seq 0 $ip_count); do
			echo $ip_hits | jq .\[$i\].EVENT.sourceIPAddress >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > ips.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' ips.tmp
		unique_ip_count=$(cat ips.tmp | wc -l | sed 's/ //g')
		echo -e "${CYAN}$unique_ip_count${NC} - Unique IP's that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			$vt_folder/virustotal/vt-ip-check.py -f ips.tmp -o $environment-ips.csv -v $vt_api_key
		else
			$vt_folder/virustotal/vt-ip-check.py -f ips.tmp -v $vt_api_key
		fi
		rm ips.tmp
	fi
fi
unset filename
unset ipaddress
unset timestamp
unset environment