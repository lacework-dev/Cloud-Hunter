#!/usr/bin/env python3

# Cloud Hunter
# Lacework Labs
# v1.01 - February 2022
# greg.foss@lacework.net

'''
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
'''

import pandas as pd
from tabulate import tabulate
from subprocess import call
import os,sys,time,datetime,argparse,requests,json,csv,toml

class bcolors:
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	GREEN = '\033[92m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	BLUEBG = '\033[44m'
	REDBG = '\033[41m'
	ENDC = '\033[0m'

banner = f'''{bcolors.BOLD}{bcolors.CYAN}                _                                    
              (`  ).                   _             
             (     ).              .:(`  )`.         
)           _(       '`.          :(   .    )        
        .=(`(      .   )     .--  `.  (    ) )       
       ((    (..__.:'-'   .+(   )   ` _`  ) )        
`.     `(       ) )       (   .  )     (   )  ._     
  )      ` __.:'   )     (   (   ))     `-'.-(`  )   
)  )  ( )       --'       `- __.'         :(      )) 
.-'  (_.'          .')                    `(    )  ))
                  (_  )                     ` __.:'  
{bcolors.RED}	  _                               
	 / `/_      _/  /_/   _  _ _/__  _
	/_,//_//_//_/  / //_// //_'/ /_'/ {bcolors.ENDC}
	                    {bcolors.BOLD}Lacework Labs{bcolors.ENDC}
'''

def parse_the_things():
	parser = argparse.ArgumentParser(description = 'Dynamically generate and hunt with the Lacework Query Language (LQL) quickly and efficiently')
	parser.add_argument('-environment', help = 'Lacework environment (will be set to "default" if not specified)', action = 'store', dest = 'lw_env')
	parser.add_argument('-any', help = 'Include literally any keyword in an LQL query (Waring: may return thousands of results)', action = 'store', dest = 'anything')
	parser.add_argument('-source', help = 'Include events by source in an LQL query', action = 'store', dest = 'evtSource')
	parser.add_argument('-event', help = 'Include specific event type in an LQL query', action = 'store', dest = 'evtName')
	parser.add_argument('-events', help = 'Include multiple events - Important - use this format: \"\'event1\',\'event2\'\"', action = 'store', dest = 'evtNames')
	parser.add_argument('-type', help = 'Include a specific event type in an LQL query', action = 'store', dest = 'evtType')
	parser.add_argument('-username', help = 'Include a username in an LQL query', action = 'store', dest = 'account')
	parser.add_argument('-ip', help = 'Include a source IP address in an LQL query', action = 'store', dest = 'srcIp')
	parser.add_argument('-userAgent', help = 'Include a User Agent string in an LQL query', action = 'store', dest = 'uaString')
	parser.add_argument('-reqParam', help ='Include a Request Parameter String in an LQL query', action = 'store', dest = 'param')
	parser.add_argument('-reqParams', help ='Include multiple Request Parameters - Important - use this format: \"\'param1\',\'param2\'\"', action = 'store', dest = 'params')
	parser.add_argument('-region', help = 'Include region within an LQL query', action = 'store', dest = 'region')
	parser.add_argument('-errorCode', help ='Include an error code in an LQL query', action	='store', dest = 'error')
	parser.add_argument('-errorCodes', help ='Include multiple error codes - Important - use this format: \"\'error1\',\'error2\'\"', action	='store', dest = 'errors')
	parser.add_argument('-accessDenied', help = 'Include Access Status in LQL query - Provide: (Y/N)', action = 'store', dest = 'status')
	parser.add_argument('-dns', help = 'Include DNS entries queried from the environment', action = 'store', dest = 'dns')
	parser.add_argument('-hostname', help = 'Include activities tied to a hostname', action = 'store', dest = 'hostname')
	parser.add_argument('-filename', help = 'Include activities tied to a filename', action = 'store', dest = 'filename')
	parser.add_argument('-cmdline', help = 'Include command line items in LQL query', action = 'store', dest = 'cmdline')
	parser.add_argument('-hunt', help = 'Hunt by executing a raw LQL query', action = 'store', dest = 'exQuery')
	parser.add_argument('-t', help ='Hunt timeframe in days (default 7-days)', action = 'store', dest = 'days')
	parser.add_argument('-r', '--run', help = 'Hunt using crafted query', action = 'store_true')
	parser.add_argument('-c', '--count', help = 'Hunt and only count the hits, do not print the details to the screen', action = 'store_true')
	parser.add_argument('-j', '--JSON', help = 'View the results as raw JSON', action = 'store_true')
	parser.add_argument('-o', help = 'Export the results in CSV format or JSON if -j argument is passed', action = 'store', dest = 'output_filename')
	return parser

def configuration(lw_env):
	
	global lw_account
	global authorization_token

	config_file = os.path.expanduser("~") + "/.lacework.toml"

	if os.path.isfile(config_file):
		toml_data = toml.load(config_file)
		lw_account = toml_data.get(lw_env).get('account')
		keyId = toml_data.get(lw_env).get('api_key')
		secret = toml_data.get(lw_env).get('api_secret')
		api_version = toml_data.get(lw_env).get('version')

		# Temporary Access Token Generation
		token_url = "https://{}.lacework.net/api/v2/access/tokens".format(lw_account)
		token_payload = json.dumps({
		  "keyId": keyId,
		  "expiryTime": 3600
		})
		token_headers = {
		  'X-LW-UAKS': secret,
		  'Content-Type': 'application/json'
		}
		token_response = requests.request("POST", token_url, headers=token_headers, data=token_payload)
		json_data = json.loads(token_response.text)
		authorization_token = json_data['token']
	else:
		print(f"{bcolors.BOLD}{bcolors.CYAN} {{}} {bcolors.ENDC}".format(banner))
		print(f"[!] {bcolors.RED}{bcolors.UNDERLINE}ERROR{bcolors.ENDC}{bcolors.RED}: Missing ~/.lacework configuration file{bcolors.ENDC}")
		print()
		print(f"{bcolors.RED}Please install and configure the Lacework CLI before proceeding...{bcolors.ENDC}")
		print()
		print("This can be installed with the following bash command:")
		print(f"{bcolors.BLUE}$ curl https://raw.githubusercontent.com/lacework/go-sdk/main/cli/install.sh | bash{bcolors.ENDC}")
		quit()

def craft_query(**arguments):
	
	global crafted_query
	global cmd_options
	global cloud_trail_activity

	joined_items = {}
	joined_options = {}
	multi_joined_items = {}
	var_count = 0
	multiVariable = 0
	for arg in arguments.items():
		variable = arg[0]
		value = arg[1]
		
		# ============================== CloudTrailRawEvents ============================== #

		# ===== Single Variable Options ===== #

		# Any Value
		if variable == 'anything':
			cloud_trail_activity = True
			var_count += 1
			if '!' in value:
				joined_options['-source \'{}\''.format(value)]='any_value'
				value = value.split("!")
				any_value = "EVENT NOT LIKE '%{}%'".format(value[1])
			else:
				any_value = "EVENT LIKE '%{}%'".format(value)
				joined_options['-source {}'.format(value)]='any_value'
			joined_items[any_value]='any_value'

		# Event Source
		if variable == 'evtSource':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				event_source = "EVENT_SOURCE IS NOT NULL"
				joined_options['-source {}'.format(value)]='event_source'
			elif '!' in value:
				joined_options['-source \'{}\''.format(value)]='event_source'
				value = value.split("!")
				event_source = "EVENT_SOURCE NOT LIKE '%{}%'".format(value[1])
			else:
				event_source = "EVENT_SOURCE LIKE '%{}%'".format(value)
				joined_options['-source {}'.format(value)]='event_source'
			joined_items[event_source]='event_source'

		# Event Region
		if variable == 'region':
			cloud_trail_activity = True
			var_count += 1
			regions = ('us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-2', 'ap-southeast-1')
			if value.lower() in regions:
				if value.lower() == 'exists':
					event_region = "EVENT:awsRegion IS NOT NULL"
					joined_options['-region {}'.format(value)]='event_region'
				else:
					event_region = "EVENT:awsRegion = '{}'".format(value)
					joined_options['-region {}'.format(value)]='event_region'
				joined_items[event_region]='event_region'
			elif '!' in value:
				joined_options['-region \'{}\''.format(value)]='event_region'
				value = value.split("!")
				if value[1] in regions:
					event_region = "EVENT:awsRegion NOT LIKE '%{}%'".format(value[1])
				else:
					print()
					print(f"[!] {bcolors.BOLD}{bcolors.RED}Please enter a valid region{bcolors.ENDC}")
					print(f"{bcolors.CYAN}Regions:{bcolors.ENDC} {{}}".format(regions))
					print()
					quit()
			else:
				print()
				print(f"[!] {bcolors.BOLD}{bcolors.RED}Please enter a valid region{bcolors.ENDC}")
				print(f"{bcolors.CYAN}Regions:{bcolors.ENDC} {{}}".format(regions))
				print()
				quit()
		
		# Event Name
		if variable == 'evtName':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				event_name = "EVENT_NAME IS NOT NULL"
				joined_options['-event {}'.format(value)]='event_name'
			elif '!' in value:
				joined_options['-event \'{}\''.format(value)]='event_name'
				value = value.split("!")
				event_name = "EVENT_NAME NOT LIKE '%{}%'".format(value[1])
			else:
				event_name = "EVENT_NAME LIKE '%{}%'".format(value)
				joined_options['-event {}'.format(value)]='event_name'
			joined_items[event_name]='event_name'

		# Event Type
		if variable == 'evtType':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				event_type = "EVENT:eventType::String IS NOT NULL"
				joined_options['-type {}'.format(value)]='event_type'
			elif '!' in value:
				joined_options['-type \'{}\''.format(value)]='event_type'
				value = value.split("!")
				event_type = "EVENT:eventType::String NOT LIKE '%{}%'".format(value[1])
			else:
				event_type = "EVENT:eventType::String LIKE '%{}%'".format(value)
				joined_options['-type {}'.format(value)]='event_type'
			joined_items[event_type]='event_type'
		
		# Username
		if variable == 'username':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				event_username = "EVENT:userIdentity.userName IS NOT NULL"
				joined_options['-username {}'.format(value)]='event_username'
			elif '!' in value:
				joined_options['-username \'{}\''.format(value)]='event_username'
				value = value.split("!")
				event_username = "EVENT:userIdentity.userName NOT LIKE '%{}%'".format(value[1])
			else:
				event_username = "EVENT:userIdentity.userName LIKE '%{}%'".format(value)
				joined_options['-username {}'.format(value)]='event_username'
			joined_items[event_username]='event_username'
		
		# Source IP
		if variable == 'srcIp':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				event_ip = "EVENT:sourceIPAddress IS NOT NULL"
				joined_options['-ip {}'.format(value)]='event_ip'
			elif '!' in value:
				joined_options['-ip \'{}\''.format(value)]='event_ip'
				value = value.split("!")
				event_ip = "EVENT:sourceIPAddress NOT LIKE '%{}%'".format(value[1])
			else:
				event_ip = "EVENT:sourceIPAddress = '{}'".format(value)
				joined_options['-ip {}'.format(value)]='event_ip'
			joined_items[event_ip]='event_ip'
			
		# User Agent
		if variable == 'uaString':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				event_ua = "EVENT:userAgent IS NOT NULL"
				joined_options['-userAgent {}'.format(value)]='event_ua'
			elif '!' in value:
				joined_options['-userAgent \'{}\''.format(value)]='event_ua'
				value = value.split("!")
				event_ua = "EVENT:userAgent NOT LIKE '%{}%'".format(value[1])
			else:
				event_ua = "EVENT:userAgent LIKE '%{}%'".format(value)
				joined_options['-userAgent {}'.format(value)]='event_ua'
			joined_items[event_ua]='event_ua'

		# Request Parameter
		if variable == 'param':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				request_param = "EVENT:requestParameters.name IS NOT NULL"
				joined_options['-request_param {}'.format(value)]='request_param'
			elif '!' in value:
				joined_options['-reqParam \'{}\''.format(value)]='request_param'
				value = value.split("!")
				request_param = "EVENT:requestParameters.name NOT LIKE '%{}%'".format(value[1])
			else:
				request_param = "EVENT:requestParameters.name LIKE '%{}%'".format(value)
				joined_options['-reqParam {}'.format(value)]='request_param'
			joined_items[request_param]='request_param'

		# Error Code
		if variable == 'error':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == 'exists':
				error_code = "ERROR_CODE IS NOT NULL"
				joined_options['-errorCode {}'.format(value)]='error_code'
			elif '!' in value:
				joined_options['-errorCode \'{}\''.format(value)]='error_code'
				value = value.split("!")
				error_code = "ERROR_CODE NOT LIKE '%{}%'".format(value[1])
			else:
				error_code = "ERROR_CODE = '{}'".format(value)
				joined_options['-errorCode {}'.format(value)]='error_code'
			joined_items[error_code]='error_code'

		# Access Denied
		if variable == 'status':
			cloud_trail_activity = True
			var_count += 1
			if value.lower() == "y":
				access_status = "ERROR_CODE IN ('AccessDenied', 'Client.UnauthorizedOperation')"
			else:
				access_status = "ERROR_CODE IS NULL"
			joined_items[access_status]='access_level'
			joined_options['-accessDenied {}'.format(value)]='access_level'

		# ===== Multi-Variable Options ===== #

		# Events
		if variable == 'evtNames':
			cloud_trail_activity = True
			var_count += 1
			multiVariable = 1
			for event_value in value:
				multi_joined_items[value]='event_value'
			multiVariableName = "EVENT_NAME"
			joined_options['-events \"{}\"'.format(value)]='event_value'

		# Request Parameters
		if variable == 'params':
			cloud_trail_activity = True
			var_count += 1
			multiVariable = 1
			for event_value in value:
				multi_joined_items[value]='request_params'
			multiVariableName = "EVENT:requestParameters.name"
			joined_options['-reqParams \"{}\"'.format(value)]='request_params'

		# Error Codes
		if variable == 'errors':
			cloud_trail_activity = True
			var_count += 1
			multiVariable = 1
			for error in value:
				multi_joined_items[value]='errors'
			multiVariableName = "ERROR_CODE"
			joined_options['-errorCodes \"{}\"'.format(value)]='errors'

		# ============================== LW_HE_MACHINES ============================== #

		if variable == 'hostname':
			lw_data_sauce = 'LW_HE_MACHINES'
			var_count += 1
			if value.lower() == 'exists':
				event_hostname = "HOSTNAME IS NOT NULL"
				joined_options['-hostname {}'.format(value)]='hostname'
			elif '!' in value:
				joined_options['-hostname \'{}\''.format(value)]='hostname'
				value = value.split("!")
				event_hostname = "HOSTNAME NOT LIKE '%{}%'".format(value[1])
			else:
				event_hostname = "HOSTNAME = '{}'".format(value)
				joined_options['-hostname {}'.format(value)]='hostname'
			joined_items[event_hostname]='hostname'

		# ============================== LW_HE_FILES ============================== #

		if variable == 'filename':
			lw_data_sauce = 'LW_HE_FILES'
			var_count += 1
			if value.lower() == 'exists':
				event_filename = "FILE_NAME IS NOT NULL"
				joined_options['-filename {}'.format(value)]='filename'
			elif '!' in value:
				joined_options['-filename \'{}\''.format(value)]='filename'
				value = value.split("!")
				event_filename = "FILE_NAME NOT LIKE '%{}%'".format(value[1])
			else:
				event_filename = "(CONTAINS(FILE_NAME, '{}'))".format(value)
				joined_options['-filename {}'.format(value)]='filename'
			joined_items[event_filename]='filename'

		# ============================== LW_HA_FILE_CHANGES ============================== #

		# ============================== LW_HA_DNS_REQUESTS ============================== #

		if variable == 'dns':
			lw_data_sauce = 'LW_HA_DNS_REQUESTS'
			var_count += 1
			if value.lower() == 'exists':
				event_dns = "HOSTNAME IS NOT NULL"
				joined_options['-dns {}'.format(value)]='dns'
			elif '!' in value:
				joined_options['-dns \'{}\''.format(value)]='dns'
				value = value.split("!")
				event_dns = "HOSTNAME NOT LIKE '%{}%'".format(value[1])
			else:
				event_dns = "(CONTAINS(HOSTNAME, '{}'))".format(value)
				joined_options['-dns {}'.format(value)]='dns'
			joined_items[event_dns]='dns'

		# ============================== LW_HA_USER_LOGINS ============================== #

		# ============================== LW_CFG_AWS ============================== #

		# ============================== LW_HE_CONTAINERS ============================== #

		# ============================== LW_HE_USERS ============================== #

		# ============================== LW_HE_PROCESSES ============================== #

		if variable == 'cmdline':
			lw_data_sauce = 'LW_HE_PROCESSES'
			var_count += 1
			if value.lower() == 'exists':
				event_cmdline = "CMDLINE IS NOT NULL"
				joined_options['-cmdline {}'.format(value)]='cmdline'
			elif '!' in value:
				joined_options['-cmdline \'{}\''.format(value)]='cmdline'
				value = value.split("!")
				event_cmdline = "CMDLINE NOT LIKE '%{}%'".format(value[1])
			else:
				event_cmdline = "CMDLINE LIKE '%{}%'".format(value)
				joined_options['-cmdline {}'.format(value)]='cmdline'
			joined_items[event_cmdline]='cmdline'

		# ============================== LW_HA_CONNECTIONS ============================== #

	# ===== Collect and organize arguments, then finalize the query ===== #

	argCount = len(arg)
	if argCount > 1:
		if multiVariable == 1:
			if var_count > 1:
				joined_args = " AND ".join(joined_items)
				multi_joined_args = ", ".join(multi_joined_items)
				final_joined_args = "{} AND {} IN ({})".format(joined_args, multiVariableName, multi_joined_args)
				query_args = final_joined_args
			else:
				multi_joined_args = ", ".join(multi_joined_items)
				query_args = "{} IN ({})".format(multiVariableName, multi_joined_args)
		else:
			joined_args = " AND ".join(joined_items)
			query_args = joined_args
		cmd_options = " ".join(joined_options)
	else:
		query_args = joined_items
		cmd_options = joined_options

	# Final Query
	if cloud_trail_activity:
		lw_data_sauce = 'CloudTrailRawEvents'
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {CloudTrailRawEvents} FILTER { %s } RETURN DISTINCT {INSERT_ID, INSERT_TIME, EVENT_TIME, EVENT}}' % query_args
	else:
		pass
	if lw_data_sauce == 'LW_HE_MACHINES':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HE_MACHINES} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, MID, HOSTNAME, DOMAIN, KERNEL, KERNEL_RELEASE, KERNEL_VERSION, OS, OS_VERSION, OS_DESC, CPU_INFO, MEMORY_INFO, MACHINE_ID, LAST_BOOT_TIME, LAST_BOOT_REASON, DEFAULT_ROUTER, TAGS, KERNEL_ARGS, ROUTE}}' % query_args
	elif lw_data_sauce == 'LW_HE_IMAGES':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HE_IMAGES} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, IMAGE_CREATED_TIME, MID, IMAGE_ID, CONTAINER_TYPE, AUTHOR, REPO, TAG, SIZE, VIRTUAL_SIZE, IMAGE_VERSION, ACTIVE_COUNT}}' % query_args
	elif lw_data_sauce == 'LW_HE_FILES':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HE_FILES} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, MID, PATH, FILE_NAME, INODE, FILE_TYPE, IS_LINK, LINK_DEST_PATH, LINK_ABS_DEST_PATH, OWNER_UID, OWNER_USERNAME, OWNER_GID, METADATA_HASH, FILEDATA_HASH, SIZE, BLOCK_SIZE, BLOCK_COUNT, FILE_ACCESSED_TIME, FILE_MODIFIED_TIME, FILE_CREATED_TIME, FILE_PERMISSIONS, HARD_LINK_COUNT}}' % query_args
	elif lw_data_sauce == 'LW_HA_FILE_CHANGES':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HA_FILE_CHANGES} FILTER { %s } RETURN DISTINCT {ACTIVITY_START_TIME, ACTIVITY_END_TIME, MID, PATH, ACTIVITY, FILEDATA_HASH, LAST_MODIFIED_TIME, SIZE}}' % query_args
	elif lw_data_sauce == 'LW_HA_DNS_REQUESTS':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HA_DNS_REQUESTS} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, MID, SRV_IP_ADDR, HOSTNAME, HOST_IP_ADDR, TTL, PKTLEN}}' % query_args
	elif lw_data_sauce == 'LW_HA_USER_LOGINS':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HA_USER_LOGINS} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, LOGIN_TIME, LOGOFF_TIME, EVENT_TYPE, MID, USERNAME, HOSTNAME, IP_ADDR, TTY, UID, GID}}' % query_args
	elif lw_data_sauce == 'LW_CFG_AWS':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_CFG_AWS} FILTER { %s } RETURN DISTINCT {QUERY_START_TIME, QUERY_END_TIME, ARN, API_KEY, SERVICE, ACCOUNT_ID, ACCOUNT_ALIAS, RESOURCE_TYPE, RESOURCE_ID, RESOURCE_REGION, RESOURCE_CONFIG, RESOURCE_TAGS, STATUS, KEYS, PROPS}}' % query_args
	elif lw_data_sauce == 'LW_HE_CONTAINERS':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HE_CONTAINERS} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, CONTAINER_START_TIME, MID, CONTAINER_ID, CONTAINER_TYPE, CONTAINER_NAME, PRIVILEGED, NETWORK_MODE, PID_MODE, IPV4, IPV6, LISTEN_PORT_MAP, VOLUME_MAP, REPO, TAG, PROPS_LABEL, PROPS_ENV}}' % query_args
	elif lw_data_sauce == 'LW_HE_USERS':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HE_USERS} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, MID, USERNAME, PRIMARY_GROUP_NAME, OTHER_GROUP_NAMES, HOME_DIR}}' % query_args
	elif lw_data_sauce == 'LW_HE_PROCESSES':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HE_PROCESSES} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, PROCESS_START_TIME, MID, PID_HASH, PID, USERNAME, EXE_PATH, CMDLINE, CWD, ROOT}}' % query_args
	elif lw_data_sauce == 'LW_HA_CONNECTIONS':
		crafted_query = 'LaceworkLabs_CloudHunter {SOURCE {LW_HA_CONNECTIONS} FILTER { %s } RETURN DISTINCT {RECORD_CREATED_TIME, CONN_START_TIME, CONN_END_TIME, MID, SRC_IP_ADDR, SRC_PORT, DST_IP_ADDR, DST_PORT, PROTOCOL, SYN, FIN, LOCAL, SESS_COUNT_IN, SESS_COUNT_OUT, PKT_PER_SESS_COUNT_IN, PKT_PER_SESS_COUNT_OUT, BYTES_PER_PKT_COUNT_IN, BYTES_PER_PKT_COUNT_OUT, SESSTIME_PER_SESS_IN, SESSTIME_PER_SESS_OUT, RESPTIME_PER_SESS_IN, RESPTIME_PER_SESS_OUT, INCOMING, OUTGOING, FIRST_KNOWN_TIME}}' % query_args

def validate_query(queryValidation):
	validation_url = "https://{}.lacework.net/api/v2/Queries/validate".format(lw_account)
	if cloud_trail_activity:
		payload = json.dumps({
		  "queryText": "{}".format(queryValidation),
		  "evaluatorId": "Cloudtrail"
		})
	else:
		payload = json.dumps({
		  "queryText": "{}".format(queryValidation),
		})
	headers = {
	  'Authorization': authorization_token,
	  'Content-Type': 'application/json'
	}
	try:
	    response = requests.request("POST", validation_url, headers=headers, data=payload)
	except requests.exceptions.RequestException as e:
	    print(f"[!] {bcolors.RED}{bcolors.UNDERLINE}Query Validation Error{bcolors.ENDC}[!]")
	    print("{}".format(e))
	print()
	if "data" in response.text:
		pass
	else:
		print(f"[!] {bcolors.RED}{bcolors.UNDERLINE}Query Validation Error{bcolors.ENDC} [!]")
		print()
		print(response.text)
		print()
		quit()

def hunt(exQuery):
	# Check if the query is valid
	validate_query(exQuery)

	# Obtain and format the Current Date and Time
	current_date = datetime.datetime.now().strftime("%Y-%m-%d")
	current_time = datetime.datetime.now().strftime("%H:%M:%S")
	date_now = current_date + "T" + current_time + ".000Z"

	# Back to the Future
	search_window = datetime.datetime.now() - datetime.timedelta(int(time_in_days))
	search_window_format = search_window.strftime("%Y-%m-%d")
	search_range = search_window_format + "T" + current_time + ".000Z"

	# Request
	execute_custom_url = "https://{}.lacework.net/api/v2/Queries/execute".format(lw_account)
	if cloud_trail_activity:
		payload = json.dumps({
			"query": {
			  "evaluatorId": "Cloudtrail",
			  "queryText": "{}".format(exQuery)
			},
			"arguments": [
			  {
			    "name": "StartTimeRange",
			    "value": "{}".format(search_range)
			  },
			  {
			    "name": "EndTimeRange",
			    "value": "{}".format(date_now)
			  }
			]
		})
	else:
		payload = json.dumps({
		  "query": {
		    "queryText": "{}".format(exQuery)
		  },
		  "arguments": [
		    {
		      "name": "StartTimeRange",
		      "value": "{}".format(search_range)
		    },
		    {
		      "name": "EndTimeRange",
		      "value": "{}".format(date_now)
		    }
		  ]
		})
	headers = {
		'Authorization': authorization_token,
		'Content-Type': 'application/json'
	}
	try:
		response = requests.request("POST", execute_custom_url, headers=headers, data=payload)
	except requests.exceptions.RequestException as e:
		print(e)
	json_data = json.loads(response.text)
	event_df = pd.DataFrame.from_dict(json_data['data'], orient='columns')
	try:
		if cloud_trail_activity:
			event_count = len(json_data['data'])
		else:
			event_count = event_df.shape[0]
			event_row_count = event_df.shape[1]
	except:
		print()
		print(f"{bcolors.RED}[!] {bcolors.UNDERLINE}ERROR{bcolors.ENDC}{bcolors.RED} [!]{bcolors.ENDC}")
		print(response.text)
		print()
		quit()

	if JSON:
		if output_filename:
			with open(output_filename, 'a', encoding='utf-8') as outfile:
				json.dump(json_data, outfile, ensure_ascii=False, indent=4)
			print()
			print(f"{bcolors.BOLD}JSON Output written to [{bcolors.CYAN}{{}}{bcolors.ENDC}{bcolors.BOLD}]{bcolors.ENDC}".format(output_filename))
			print()
			quit()
		else:
			json_formatted_data = json.dumps(json_data['data'], indent=4)
			print(json_formatted_data)
			quit()

	# CLOUDTRAIL SPECIFIC PARSING
	if cloud_trail_activity:
		events_table = [['Event', 'Region', 'Source', 'Time', 'Type', 'Username', 'Source IP']]

		if output_filename:
			fields = ['Event', 'Region', 'Source', 'Time', 'Type', 'Username', 'Source IP', 'User Agent', 'Access Key ID', 'Account ID', 'Recipient Account ID', 'ARN', 'Principal ID', 'Session Context', 'Type', 'Category', 'Event ID', 'Request ID', 'Version', 'Management Event', 'Read Only', 'User Identity', 'Resources', 'Request Parameters', 'TLS Details', 'Query']
			with open(output_filename, "a") as csvfile:
				csvwriter = csv.writer(csvfile)
				csvwriter.writerow(fields)

		for d in range(event_count):
			try:
				event_awsRegion = json_data['data'][d]['EVENT']['awsRegion']
			except:
				event_awsRegion = "N/A"
			try:
				event_eventCategory = json_data['data'][d]['EVENT']['eventCategory']
			except:
				event_eventCategory = "N/A"
			try:
				event_eventID = json_data['data'][d]['EVENT']['eventID']
			except:
				event_eventID = "N/A"
			try:
				event_eventName = json_data['data'][d]['EVENT']['eventName']
			except:
				event_eventName = "N/A"
			try:
				event_eventSource = json_data['data'][d]['EVENT']['eventSource']
			except:
				event_eventSource = "N/A"
			try:
				event_eventTime = json_data['data'][d]['EVENT']['eventTime']
			except:
				event_eventTime = "N/A"
			try:
				event_eventType = json_data['data'][d]['EVENT']['eventType']
			except:
				event_eventType = "N/A"
			try:
				event_eventVersion = json_data['data'][d]['EVENT']['eventVersion']
			except:
				event_eventVersion = "N/A"
			try:
				event_managementEvent = json_data['data'][d]['EVENT']['managementEvent']
			except:
				event_managementEvent = "N/A"
			try:
				event_readOnly = json_data['data'][d]['EVENT']['readOnly']
			except:
				event_readOnly = "N/A"
			try:
				event_recipientAccountId = json_data['data'][d]['EVENT']['recipientAccountId']
			except:
				event_recipientAccountId = "N/A"
			try:
				event_requestID = json_data['data'][d]['EVENT']['requestID']
			except:
				event_requestID = "N/A"
			try:
				event_sourceIPAddress = json_data['data'][d]['EVENT']['sourceIPAddress']
			except:
				event_sourceIPAddress = "N/A"
			try:
				event_userAgent = json_data['data'][d]['EVENT']['userAgent']
			except:
				event_userAgent = "N/A"
			try:
				event_resources = json_data['data'][d]['EVENT']['resources']
			except:
				event_resources = "N/A"
			try:
				event_requestParameters = json_data['data'][d]['EVENT']['requestParameters']
			except:
				event_requestParameters = "N/A"
			try:
				event_tlsDetails = json_data['data'][d]['EVENT']['tlsDetails']
			except:
				event_tlsDetails = "N/A"
			try:
				event_userIdentity= json_data['data'][d]['EVENT']['userIdentity']
			except:
				event_userIdentity = "N/A"
			try:
				event_accountId = json_data['data'][d]['EVENT']['userIdentity']['accountId']
			except:
				event_accountId = "N/A"
			try:
				event_arn = json_data['data'][d]['EVENT']['userIdentity']['arn']
			except:
				event_arn = "N/A"
			try:
				event_principalId = json_data['data'][d]['EVENT']['userIdentity']['principalId']
			except:
				event_principalId = "N/A"
			try:
				event_type = json_data['data'][d]['EVENT']['userIdentity']['type']
			except:
				event_type = "N/A"
			try:
				event_userName = json_data['data'][d]['EVENT']['userIdentity']['userName']
			except:
				event_userName = "N/A"
			try:
				event_accessKeyId = json_data['data'][d]['EVENT']['userIdentity']['accessKeyId']
			except:
				event_accessKeyId = "N/A"
			try:
				event_sessionContext = json_data['data'][d]['EVENT']['userIdentity']['sessionContext']
			except:
				event_sessionContext = "N/A"

			# Append JSON Data to Table for printing to screen
			if event_count >= 2:
				events_table += [[event_eventName, event_awsRegion, event_eventSource, event_eventTime, event_eventType, event_userName, event_sourceIPAddress]]

			# Output full dataset to CSV if desired
			if output_filename:
				row = [event_eventName, event_awsRegion, event_eventSource, event_eventTime, event_eventType, event_userName, event_sourceIPAddress, event_userAgent, event_accessKeyId, event_accountId, event_recipientAccountId, event_arn, event_principalId, event_sessionContext, event_type, event_eventCategory, event_eventID, event_requestID, event_eventVersion, event_managementEvent, event_readOnly, event_userIdentity, event_resources, event_requestParameters, event_tlsDetails, exQuery]
				with open(output_filename, "a") as csvfile:
					csvwriter = csv.writer(csvfile)
					csvwriter.writerow(row)

	# FOR EVERYTHING BUT CLOUDTRAIL
	else:
		if output_filename:
			event_df.to_csv(output_filename, index=False)

	if event_count == 0:
		if count:
			print(f"[!] {bcolors.BOLD}{bcolors.RED}No Events found over a {bcolors.ENDC}{bcolors.BOLD}{{}}{bcolors.RED}-day search period{bcolors.ENDC}".format(time_in_days))
			print()
		else:
			print(f"[!] {bcolors.BOLD}{bcolors.RED}No Events found over a {bcolors.ENDC}{bcolors.BOLD}{{}}{bcolors.RED}-day search period{bcolors.ENDC}".format(time_in_days))
			print(exQuery)
			print()
	elif event_count == 1:
		if count:
			print(f"[*] {bcolors.GREEN}1{bcolors.ENDC} Event returned over a {bcolors.GREEN}{{}}{bcolors.ENDC}-day search period".format(time_in_days))
			print()
		else:
			print(f"[*] {bcolors.GREEN}1{bcolors.ENDC} Event returned over a {bcolors.GREEN}{{}}{bcolors.ENDC}-day search period".format(time_in_days))
			print()
			print(f"{bcolors.BOLD}Event Details{bcolors.ENDC}")
			if cloud_trail_activity:
				event_table = [['Event:', '{}'.format(event_eventName)]]
				event_table += [['Region:', '{}'.format(event_awsRegion)]]
				event_table += [['Source:', '{}'.format(event_eventSource)]]
				event_table += [['Time:', '{}'.format(event_eventTime)]]
				event_table += [['Type:', '{}'.format(event_eventType)]]
				event_table += [['Username:', '{}'.format(event_userName)]]
				event_table += [['Source IP:', '{}'.format(event_sourceIPAddress)]]
				event_table += [['User Agent:', '{}'.format(event_userAgent)]]
				event_table += [['Access Key ID:', '{}'.format(event_accessKeyId)]]
				event_table += [['Account ID:', '{}'.format(event_accountId)]]
				event_table += [['Recipient Account ID:', '{}'.format(event_recipientAccountId)]]
				event_table += [['ARN:', '{}'.format(event_arn)]]
				event_table += [['Principal ID:', '{}'.format(event_principalId)]]
				event_table += [['Type:', '{}'.format(event_type)]]
				event_table += [['Category:', '{}'.format(event_eventCategory)]]
				event_table += [['Event ID:', '{}'.format(event_eventID)]]
				event_table += [['Request ID:', '{}'.format(event_requestID)]]
			else:
				event_table = []
				for col in event_df:
					event_value = event_df[col]
					event_table += [[col, event_value.to_string(index=False)]]
			print(tabulate(event_table))
			print()
			print(f"{bcolors.BOLD}Query:{bcolors.ENDC}")
			print(exQuery)
			print()
			if output_filename:
				print(f"{bcolors.BOLD}Event written to [{bcolors.CYAN}{{}}{bcolors.ENDC}{bcolors.BOLD}]{bcolors.ENDC}".format(output_filename))
				print()
			else:
				print("For additional information, export event details to a file:")
				if query_contents:
					print(f"{bcolors.BLUE}$ ./{script_name} {{}} -r -o <output_file.csv>{bcolors.ENDC}".format(cmd_options))
				else:
					print(f"{bcolors.BLUE}$ ./{script_name} -hunt <query> -o <output_file.csv>{bcolors.ENDC}")
				print()
	elif event_count >= 2:
		if count:
			print(f"[*] Found [{bcolors.GREEN}{{}}{bcolors.ENDC}] events over a {bcolors.GREEN}{{}}{bcolors.ENDC}-day search period".format(event_count,time_in_days))
			print()
		else:
			print(f"[*] Found [{bcolors.GREEN}{{}}{bcolors.ENDC}] events over a {bcolors.GREEN}{{}}{bcolors.ENDC}-day search period:".format(event_count,time_in_days))
			print()
			if cloud_trail_activity:
				print(tabulate(events_table, headers='firstrow'))
			else:
				print(event_df)
			print()
			print(f"{bcolors.BOLD}{bcolors.CYAN}Query:{bcolors.ENDC}")
			print(exQuery)
			print()
			if output_filename:
				print(f"{bcolors.BOLD}{bcolors.GREEN}{{}}{bcolors.ENDC}{bcolors.BOLD} Events written to [{bcolors.CYAN}{{}}{bcolors.ENDC}{bcolors.BOLD}]{bcolors.ENDC}".format(event_count,output_filename))
				print()
			else:
				print("For additional information, export event details to a file:")
				if query_contents:
					print(f"{bcolors.BLUE}$ ./{script_name} {{}} -r -o <output_file.csv>{bcolors.ENDC}".format(cmd_options))
				else:
					print(f"{bcolors.BLUE}$ ./{script_name} -hunt <query> -o <output_file.csv>{bcolors.ENDC}")
				print()

def main():
	# Argument Parsing
	parser = parse_the_things()
	args = parser.parse_args()

	# cloud-hunter script
	global script_name
	script_name = os.path.basename(__file__)

	# Global Hunting Terms
	global query_contents
	global event_source
	global username
	query_contents = {}
	event_source = ''
	username = ''
	if args.anything:
		query_contents['anything']='{}'.format(args.anything)
	if args.region:
		query_contents['region']='{}'.format(args.region)
	if args.evtSource:
		query_contents['evtSource']='{}'.format(args.evtSource)
	if args.evtName:
		query_contents['evtName']='{}'.format(args.evtName)
	if args.evtNames:
		query_contents['evtNames']='{}'.format(args.evtNames)
	if args.evtType:
		query_contents['evtType']='{}'.format(args.evtType)
	if args.account:
		query_contents['username']='{}'.format(args.account)
	if args.srcIp:
		query_contents['srcIp']='{}'.format(args.srcIp)
	if args.uaString:
		query_contents['uaString']='{}'.format(args.uaString)
	if args.param:
		query_contents['param']='{}'.format(args.param)
	if args.params:
		query_contents['params']='{}'.format(args.params)
	if args.error:
		query_contents['error']='{}'.format(args.error)
	if args.errors:
		query_contents['errors']='{}'.format(args.errors)
	if args.status:
		query_contents['status']='{}'.format(args.status)
	if args.hostname:
		query_contents['hostname']='{}'.format(args.hostname)
	if args.filename:
		query_contents['filename']='{}'.format(args.filename)
	if args.cmdline:
		query_contents['cmdline']='{}'.format(args.cmdline)
	if args.dns:
		query_contents['dns']='{}'.format(args.dns)

	# Global timeframe
	global time_in_days
	if args.days:
		time_in_days = args.days
	else:
		time_in_days = 7

	# Global Counter
	if args.count:
		global count
		count = args.count
	else:
		count = ''

	# Global File Writer
	if args.output_filename:
		global output_filename
		output_filename = args.output_filename
	else:
		output_filename = ''

	# Dump Raw JSON
	if args.JSON:
		global JSON
		JSON = args.JSON
	else:
		JSON = ''

	# Only query cloudtrail data if explicitly triggered
	global cloud_trail_activity 
	cloud_trail_activity = False

	if args.exQuery:
		# Authentication
		if args.lw_env:
			configuration(args.lw_env)
		else:
			lw_env = "default"
			configuration(lw_env)
		# Hunt
		hunt(args.exQuery)
	elif args.run:
		# Authentication
		if args.lw_env:
			configuration(args.lw_env)
		else:
			lw_env = "default"
			configuration(lw_env)
		# Hunt
		craft_query(**query_contents)
		hunt(crafted_query)
	elif query_contents:
		craft_query(**query_contents)
		print()
		print(f"[*] {bcolors.BOLD}{bcolors.GREEN}Generated Query:{bcolors.ENDC}")
		print(crafted_query)
		print()
		print("To hunt with this query, append -r during execution:")
		print(f"{bcolors.BLUE}$ ./{script_name} {{}} -r {bcolors.ENDC}".format(cmd_options))
	else:
		print(f"{{}}".format(banner))
		print(parser.format_help())
		quit()

if __name__ == "__main__":
	main()