#!/bin/bash

# Large Scale Cloud Hunter
# Lacework Labs
# v0.2 - February 2022
# greg.foss@lacework.net
#
# Use alongside cloud-hunter.py to run queries across multiple environments
#
# EDIT THE CONFIGURATION FILE TO UPDATE SCRIPT OPTIONS
# ==============================
configuration_file="./config.json"
# ==============================

primary_env=$(cat $configuration_file | jq ."primary_lacework_tenant_name" | tr -d '"')
cloud_hunter=$(cat $configuration_file | jq ."cloud_hunter_script_location" | tr -d '"')

CYAN='\033[0;36m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

banner="""
                .   Cloud-Hunter   |      *
     *             *              -O-          .
           .             *         |     ,
          .---.
    =   _/__~0_\_     .  *  Scale-Hunt   o    '
   = = (_________)             .
                   .                        *
         *               - ) -       *
                . Lacework Labs .
"""

count_loop () {
	env=$(echo $i | cut -d "[" -f 2 | cut -d "]" -f 1);
	output=$($cloud_hunter $@ -environment $env);
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
	output=$($cloud_hunter $@ -environment $env | grep -v "Query:\|LaceworkLabs_AWS_CloudHunter\|additional details\|filename.csv")
	if [[ "$env" == *default* ]]
	then
		env=$primary_env
	fi
	echo -e ${CYAN}$env${NC}
	echo "$output"
	echo
	echo
}

if [[ $# -eq 0 ]]
then
    echo -e "${BLUE}$banner${NC}"
    echo -e "====================[ ${GREEN}HELP${NC} ]===================="
    echo -e "${CYAN}scale-hunt.sh${NC} takes the same arguments as ${CYAN}cloud-hunter.py${NC}"
    echo
    echo -e "${CYAN}Run the script without options to view available options:${NC}"
    echo "$ $cloud_hunter"
    echo "=================================================="
    echo
    exit 1
fi
if [[ "$*" == *-c* ]]
then
	echo
	printf "${CYAN}Environment${NC}	|	${CYAN}Hits${NC}\n"
	echo -e "${BLUE}==============================${NC}"
	for i in $(grep "\[" ~/.lacework.toml); do count_loop "$@" &  done
	wait
else
	echo
	for i in $(grep "\[" ~/.lacework.toml); do detailed_loop "$@" & done
	wait
fi
echo