#!/bin/bash

# VirusTotal Indicator Huntor
# Lacework Labs
# v0.2 - February 2022
# greg.foss@lacework.net
#
# Use alongside cloud-hunter.py to evaluate Files, Domains, and IP's with VirusTotal

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

while getopts f:d:i:t:e: flag
do
	case "${flag}" in
		f) filename=${OPTARG};;
		d) domain=${OPTARG};;
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
	echo "$ ./virustotal-hunt -f \"filename\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo "Hunt via Domain:"
	echo "$ ./virustotal-hunt -d \"domain\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo "Hunt via IP Address:"
	echo "$ ./virustotal-hunt -i \"ip address\" -t \"timeframe in days\" -e \"Lacework environment\""
	echo ""
	echo "Filename, Domain, or IP Address are required"
	echo "Timeframe and Environment are optional"
	echo
	echo "=================================================="
	echo 
else
	echo
	
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
		echo "$file_count - Total files found"
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
	
	# Domain Hunting
	elif [[ $domain != $null ]]; then
		if [[ $domain == 'exists' ]]; then
			echo "Checking all DNS queries - this may take a long time..."
			echo "Results are limited to the most recent 5000 hits"
		fi
		if [[ $time != $null ]]; then
			if [[ $environment != $null ]]; then
				dns_hits=$(../cloud-hunter.py -dns $domain -r -j -t $time -environment $environment)
			else
				dns_hits=$(../cloud-hunter.py -dns $domain -r -j -t $time)
			fi
		else
			if [[ $environment != $null ]]; then
				dns_hits=$(../cloud-hunter.py -dns $domain -r -j -environment $environment)
			else
				dns_hits=$(../cloud-hunter.py -dns $domain -r -j)
			fi
		fi
		dns_count=$(echo $dns_hits | jq '. | length')
		echo "$dns_count - Total Domains found"
		for i in $(seq 0 $dns_count); do
			echo $dns_hits | jq .\[$i\].HOSTNAME >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > dns.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' dns.tmp
		unique_dns_count=$(cat dns.tmp | wc -l | sed 's/ //g')
		echo "$unique_dns_count - Unique Domains that will be analyzed"
		echo ""
		if [[ $environment != $null ]]; then
			./virustotal/vt-dns-check.py -f dns.tmp -o $environment-dns.csv
		else
			./virustotal/vt-dns-check.py -f dns.tmp
		fi
		rm dns.tmp

	# IP Hunting
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
		echo "$ip_count - Total IP's found"
		for i in $(seq 0 $ip_count); do
			echo $ip_hits | jq .\[$i\].EVENT.sourceIPAddress >> tmp.tmp
		done
		cat tmp.tmp | grep -v 'null\|^$' | sort -u | tr -d '"' > ips.tmp
		rm tmp.tmp
		sed -i "" '/^[[:space:]]*$/d' ips.tmp
		unique_ip_count=$(cat ips.tmp | wc -l | sed 's/ //g')
		echo "$unique_ip_count - Unique IP's that will be analyzed"
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