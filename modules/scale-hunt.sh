#!/bin/bash

# Large Scale Cloud Hunter
# Lacework Labs
# v0.1 - September 2021
# greg.foss@lacework.net
#
# Use alongside cloud-hunter.py to run queries across multiple environments

# EDIT THESE VARIABLES
# ==============================
# How you'd like to display the default environment within output
primary_env='default'
# Cloud Hunter script location
cloud_hunter='../cloud-hunter.py'
# ==============================

CYAN='\033[0;36m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

count_loop () {
	env=$(echo $i | cut -d "[" -f 2 | cut -d "]" -f 1);
	if [[ "$*" != *-r* ]]
	then
		output=$($cloud_hunter $@ -r -environment $env);
	else
		output=$($cloud_hunter $@ -environment $env);
	fi
	if [[ "$env" == *default* ]]
	then
		env=$primary_env
	fi
	clean_output=$(echo $output | cut -d "]" -f 2 | cut -d " " -f 2 | cut -d " " -f 1);
	if [[ "$output" == *!* ]]
	then
		clean_output=$(echo -e "${RED}0${NC}")
	elif [[ "$output" == *events* ]]
	then
		new_output=$(echo $output | cut -d "]" -f 2 | cut -d "[" -f 3 | cut -d "m" -f 2);
		clean_output=$(echo -e "${GREEN}$new_output${NC}")
	else
		clean_output=$(echo -e "${GREEN}$clean_output${NC}")
	fi
	printf "%-10s	|	%10s\n" $env $clean_output
}

detailed_loop () {
	env=$(echo $i | cut -d "[" -f 2 | cut -d "]" -f 1);
	if [[ "$*" != *-r* ]]
	then
		output=$($cloud_hunter $@ -r -environment $env | grep -v "Query:\|LaceworkLabs_AWS_CloudHunter\|additional details\|filename.csv")
	else
		output=$($cloud_hunter $@ -environment $env | grep -v "Query:\|LaceworkLabs_AWS_CloudHunter\|additional details\|filename.csv")
	fi
	if [[ "$env" == *default* ]]
	then
		env=$primary_env
	fi
	echo -e ${CYAN}$env${NC}
	echo "$output"
	echo
	echo
}

echo
if [[ $# -eq 0 ]]
then
    echo -e "[!] ${RED}ERROR: No arguments provided${NC}"
    echo -e "Scale-Hunt.sh takes the same arguments as Cloud-Hunter.py. See the script help for reference:"
    echo -e "${CYAN}./cloud-hunter.py${NC}"
    echo
    exit 1
fi
if [[ "$*" == *-c* ]]
then
	printf "${CYAN}Environment${NC}	|	${CYAN}Hits${NC}\n"
	echo -e "${BLUE}==============================${NC}"
	for i in $(grep "\[" ~/.lacework.toml); do count_loop "$@" &  done
	wait
else
	for i in $(grep "\[" ~/.lacework.toml); do detailed_loop "$@" & done
	wait
fi