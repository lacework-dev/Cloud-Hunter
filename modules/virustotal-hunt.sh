#!/bin/bash

# VirusTotal Indicator Huntor
# Lacework Labs
# v0.1 - February 2022
# greg.foss@lacework.net
#
# Use alongside cloud-hunter.py to evaluate Files, IP's, and Domains with VirusTotal

banner="""
(             )
 \`--(_   _)--'
      Y-Y
     /@@ \\   CloudHunter
    /     \\  >>---VT--->
    \`--'.  \             ,
        |   \`.__________/)
           Lacework Labs
"""

while getopts f:i:t:e: flag
do
	case "${flag}" in
		f) filename=${OPTARG};;
		i) ipaddress=${OPTARG};;
		t) time=${OPTARG};;
		e) environment=${OPTARG};;
	esac
done
if [[ $1 == $null ]]; then
	echo "$banner"
	echo "====================[ HELP ]===================="
	echo 
	echo "Hunt via Filename or File Extension (.py):"
	echo "	$ ./virustotal-hunt -f \"filename\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo "Hunt via IP Address or Domain:"
	echo "	$ ./virustotal-hunt -i \"ip address\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo "Filename or IP Address are required"
	echo "Timeframe and Environment are optional"
	echo
	echo "=================================================="
	echo 
else
	echo "$banner"
	
	# Filename Hunting
	if [[ $filename != $null ]]; then
		if [[ $filename == 'exists' ]]; then
			echo "Checking all files - this may take a long time..."
			echo "Results are limited to the most recent 5000 hits"
		fi
		if [[ $time != $null ]]; then
			if [[ $environment != $null ]]; then
				file_hits=$(../cloud-hunter.py -filename $filename -r -j -t $time -environment $environment)
			else
				file_hits=$(../cloud-hunter.py -filename $filename -r -j -t $time)
			fi
		else
			if [[ $environment != $null ]]; then
				file_hits=$(../cloud-hunter.py -filename $filename -r -j -environment $environment)
			else
				file_hits=$(../cloud-hunter.py -filename $filename -r -j)
			fi
		fi
		file_count=$(echo $file_hits | jq '. | length')
		echo "$file_count - total files found"
		for i in $(seq 0 $file_count); do
			echo $file_hits | jq .\[$i\].FILEDATA_HASH >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > hashes.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' hashes.tmp
		unique_file_count=$(cat hashes.tmp | wc -l | sed 's/ //g')
		echo "$unique_file_count - Unique files that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			./virustotal/vt-hash-check.py -f hashes.tmp -o $environment-hashes.csv
		else
			./virustotal/vt-hash-check.py -f hashes.tmp
		fi
		rm hashes.tmp
	
	# IP / Domain Hunting
	elif [[ $ipaddress != $null ]]; then
		if [[ $ipaddress == 'exists' ]]; then
			echo "Checking all IP's - this may take a long time..."
			echo "Results are limited to the most recent 5000 hits"
		fi
		if [[ $time != $null ]]; then
			if [[ $environment != $null ]]; then
				ip_hits=$(../cloud-hunter.py -ip $ipaddress -r -j -t $time -environment $environment)
			else
				ip_hits=$(../cloud-hunter.py -ip $ipaddress -r -j -t $time)
			fi
		else
			if [[ $environment != $null ]]; then
				ip_hits=$(../cloud-hunter.py -ip $ipaddress -r -j -environment $environment)
			else
				ip_hits=$(../cloud-hunter.py -ip $ipaddress -r -j)
			fi
		fi
		ip_count=$(echo $ip_hits | jq '. | length')
		echo "$ip_count - total IP's Domains found"
		for i in $(seq 0 $ip_count); do
			echo $ip_hits | jq .\[$i\].EVENT.sourceIPAddress >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > ips.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' ips.tmp
		unique_ip_count=$(cat ips.tmp | wc -l | sed 's/ //g')
		echo "$unique_ip_count - Unique IP's / Domains that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			./virustotal/vt-ip-check.py -f ips.tmp -o $environment-ips.csv
		else
			./virustotal/vt-ip-check.py -f ips.tmp
		fi
		rm ips.tmp
	fi
fi
unset filename
unset ipaddress
unset time
unset environment