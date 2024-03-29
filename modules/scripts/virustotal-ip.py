#!/usr/bin/env python3

# VirusTotal IP Check
# Lacework Labs
# v0.3 - February, 2022
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

import sys, argparse, json, csv, requests
from tabulate import tabulate
from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError

def parse_all_things():
	parser = argparse.ArgumentParser(description = 'Analyze IP Addresses with the VirusTotal AP')
	parser.add_argument('-a', '--ip', help = 'Analyze a single IP Address', dest = 'search_term')
	parser.add_argument('-f', '--file', help = 'Analyze a list of IP addresses stored within a file', dest = 'file')
	parser.add_argument('-q', '--quota', help = 'Inspect your current VirusTotal usage - supply your username', dest = 'username')
	parser.add_argument('-o', '--outfile', help = 'Output the results of multi-IP analysis, default value -> vt-ip.csv', default = 'vt-ip.csv', dest = 'outfile')
	parser.add_argument('-v', '--vtkey', help = 'Virus Total API Key', default = 'api-key', dest = 'vt_api_key')
	return parser

def check_ip(search_term,vt_api_key):
	
	global malicious
	global suspicious
	global undetected
	global vt_link
	global comment
	global comments

	global error
	error = False

	vt_api_ip_addresses = VirusTotalAPIIPAddresses(f'{vt_api_key}')

	try:
		result = vt_api_ip_addresses.get_report(f'{search_term}')
	except VirusTotalAPIError as err:
		print(err, err.err_code)
	else:
		if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
			result = json.loads(result)
			malicious = result['data']['attributes']['last_analysis_stats']['malicious']
			suspicious = result['data']['attributes']['last_analysis_stats']['suspicious']
			undetected = result['data']['attributes']['last_analysis_stats']['undetected']
			vt_link = result['data']['links']['self']
		else:
			print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
			error = True
	if error:
		pass
	else:
		if malicious >= 1:
			try:
				result = vt_api_ip_addresses.get_comments(f'{search_term}')
			except VirusTotalAPIError as err:
				print(err, err.err_code)
			else:
				if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
					result = json.loads(result)
					try:
						comment_count = int(result['meta']['count'])
						comments = []
						comment = result['data'][0]['attributes']['text']
						for i in range(0, comment_count):
							try:
								comments += [result['data'][i]['attributes']['text']]
							except:
								pass
					except:
						comment = 'n/a'
						comments = 'n/a'
				else:
					print('HTTP Error [' + str(vt_api_ip_addresses.get_last_http_error()) +']')
		else:
			comment = 'n/a'
			comments = 'n/a'

def print_multiple_results(outfile,ip_list,vt_api_key):
	
	vt_api_ip_addresses = VirusTotalAPIIPAddresses(f'{vt_api_key}')

	print('Printing data out to %s...' % outfile)
	print('[count] - IP | Malicious | Suspicious | Undetected | Comment')
	with open(outfile,'a') as out:
		csv_out=csv.writer(out)
		csv_out.writerow(['IP','Malicious','Suspicious','Undetected','Comment','Link'])
		count = 0
		for i in ip_list:
			count += 1
			if count == 4001: # limited based on standard API licensing
				quit()
			else:
				pass
			check_ip(i,vt_api_key)
			if error:
				pass
			else:
				print(f'[{count}] - {i} | {malicious} | {suspicious} | {undetected} | {comment}')
				if malicious >= 1:
					count += 1
					# uncomment these two lines to only track malicious hits:
					#row = [i,malicious,suspicious,undetected,comment,vt_link]
					#csv_out.writerow(row)
				else:
					pass
				# if only tracking malicious hits - comment out these two lines:
				row = [i,malicious,suspicious,undetected,comment,vt_link]
				csv_out.writerow(row)

def print_single_result(search_term):
	if error:
		pass
	else:
		hits_table = [['IP:', f'{search_term}']]
		hits_table += [['Malicious:', f'{malicious}']]
		hits_table += [['Suspicious:', f'{suspicious}']]
		hits_table += [['Undetected:', f'{undetected}']]
		hits_table += [['VT Link:', f'{vt_link}']]
		print('')
		print(tabulate(hits_table))
		print('')
		if comments != 'n/a':
			print('Comments: ')
			print('--------------------')
			c_count = 0
			for c in comments:
				c_count += 1
				print(f'[{c_count}]')
				print(f'{c}')
				print('--------------------')
			print('')

def quota(username,vt_api_key):
	url = f'https://www.virustotal.com/api/v3/users/{username}/api_usage'
	payload = {}
	headers = {
		'x-apikey': f'{vt_api_key}'
	}
	response = requests.request('GET', url, headers=headers, data=payload)
	print(response.text)

def main():
	parser = parse_all_things()
	args = parser.parse_args()
	
	if args.search_term:
		check_ip(args.search_term,args.vt_api_key)
		print_single_result(args.search_term)
	elif args.file:
		with open(args.file) as f:
			ip_list = f.readlines()
			ip_list = [x.strip() for x in ip_list]
			print_multiple_results(args.outfile,ip_list,args.vt_api_key)
	elif args.username:
		quota(args.username,args.vt_api_key)
	else:
		print((parser.format_help()))
		quit()

if __name__ == "__main__":
	main()
