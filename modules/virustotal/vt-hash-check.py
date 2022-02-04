#!/usr/bin/env python3

# VirusTotal Hash Check
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
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError

def parse_all_things():
	parser = argparse.ArgumentParser(description = 'Analyze Hashes with the VirusTotal API')
	parser.add_argument('-a', '--hash', help = 'Analyze a single hash', dest = 'search_term')
	parser.add_argument('-f', '--file', help = 'Analyze a list of hashes stored within a file', dest = 'file')
	parser.add_argument('-u', '--upload', help = 'Upload a sample', dest = 'upload_sample')
	parser.add_argument('-d', '--download', help = 'Download a file', dest = 'download_link')
	parser.add_argument('-q', '--quota', help = 'Inspect your current VirusTotal usage - supply your username', dest = 'username')
	parser.add_argument('-o', '--outfile', help = 'Output the results of multi-hash analysis, default value -> vt-hash.csv', default = 'vt-hash.csv', dest = 'outfile')
	parser.add_argument('-v', '--vtkey', help = 'Virus Total API Key', default = '[PLACE API KEY HERE]', dest = 'vt_api_key')
	return parser

def check_hash(search_term,vt_api_key):
	
	global result
	global filetype
	global exif_data
	global md5
	global sha1
	global sha256
	global ssdeep
	global packers
	global last_modified
	global analysis_harmless
	global analysis_unsupported
	global analysis_suspicious
	global analysis_cnftimeout
	global analysis_timeout
	global analysis_failure
	global analysis_malicious
	global analysis_undetected
	global analysis_reputation
	global vt_link
	global comment
	
	global error
	error = False
	
	vt_api_files = VirusTotalAPIFiles(f'{vt_api_key}')

	try:
		result = vt_api_files.get_report(search_term)
	except VirusTotalAPIError as err:
		print(err, err.err_code)
	else:
		if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
			result = json.loads(result)
			filetype = result['data']['attributes']['type_description']
			try:
				exif_data = result['data']['attributes']['exiftool']
			except:
				exif_data = 'n/a'
			md5 = result['data']['attributes']['md5']
			sha1 = result['data']['attributes']['sha1']
			sha256 = result['data']['attributes']['sha256']
			ssdeep = result['data']['attributes']['ssdeep']
			last_modified = result['data']['attributes']['last_modification_date']
			analysis_harmless = result['data']['attributes']['last_analysis_stats']['harmless']
			analysis_unsupported = result['data']['attributes']['last_analysis_stats']['type-unsupported']
			analysis_suspicious = result['data']['attributes']['last_analysis_stats']['suspicious']
			analysis_cnftimeout = result['data']['attributes']['last_analysis_stats']['confirmed-timeout']
			analysis_timeout = result['data']['attributes']['last_analysis_stats']['timeout']
			analysis_failure = result['data']['attributes']['last_analysis_stats']['failure']
			analysis_malicious = result['data']['attributes']['last_analysis_stats']['malicious']
			analysis_undetected = result['data']['attributes']['last_analysis_stats']['undetected']
			analysis_reputation = result['data']['attributes']['reputation']
			vt_link = result['data']['links']['self']
			try:
				packers = result['data']['attributes']['packers']
			except:
				packers = 'n/a'
		else:
			print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
			error = True

	if error:
		pass
	else:
		if int(analysis_malicious) >= 1:
			try:
				result = vt_api_files.get_comments(f'{search_term}')
			except VirusTotalAPIError as err:
				print(err, err.err_code)
			else:
				if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
					result = json.loads(result)
					try:
						comment_count = int(result['meta']['count'])
						comment = []
						for i in range(0, comment_count):
							try:
								comment += [result['data'][i]['attributes']['text']]
							except:
								pass
					except:
						comment = 'n/a'
				else:
					print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
		else:
			comment = 'n/a'

def upload_file(search_term,vt_api_key):

	vt_api_files = VirusTotalAPIFiles(f'{vt_api_key}')

	try:
		result = vt_api_files.upload(search_term)
	except VirusTotalAPIError as err:
		print(err, err.err_code)
		quit()
	else:
		if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
			result = json.loads(result)
			result = json.dumps(result, sort_keys=False, indent=4)
			print(result)
		else:
			print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
			quit()

def download_file(search_term,vt_api_key):

	vt_api_files = VirusTotalAPIFiles(f'{vt_api_key}')

	try:
		result = vt_api_files.get_download_url(search_term)
	except VirusTotalAPIError as err:
		print(err, err.err_code)
		quit()
	else:
		if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
			result = json.loads(result)
			result = json.dumps(result, sort_keys=False, indent=4)
			print(result)
		else:
			print('HTTP Error [' + str(vt_api_files.get_last_http_error()) +']')
			quit()

def print_multiple_results(outfile,hash_list,vt_api_key):
	print('Printing data out to %s...' % outfile)
	print('[count] - Hash | Filetype | MD5 | SHA1 | SHA256 | SSDeep | Packer | Reputation | Malicious | Suspicious | Undetected | Unsupported | Failure | Comments')
	with open(outfile,'a') as out:
		csv_out=csv.writer(out)
		csv_out.writerow(['Hash','Filetype','MD5','SHA1','SHA256','SSDeep','Packer','Reputation','Malicious','Suspicious','Undetected','Unsupported','Failure','Comments','Link'])
		count = 0
		for i in hash_list:
			count += 1
			if count == 4001: # limited based on standard API licensing
				quit()
			else:
				pass
			check_hash(i,vt_api_key)
			if error:
				pass
			else:
				print(f'[{count}] - {i} | {filetype} | {packers} | {analysis_reputation} | {analysis_malicious} | {analysis_suspicious} | {analysis_undetected} | {analysis_unsupported} | {analysis_failure}')
				if int(analysis_malicious) >= 1:
					count += 1
					# uncomment these two lines to only track malicious hits
					#row = [i,filetype,md5,sha1,sha256,ssdeep,packers,analysis_reputation,analysis_malicious,analysis_suspicious,analysis_undetected,analysis_unsupported,analysis_failure,comment,vt_link]
					#csv_out.writerow(row)
				else:
					pass
				# if only tracking malicious hits - comment out these two lines:
				row = [i,filetype,md5,sha1,sha256,ssdeep,packers,analysis_reputation,analysis_malicious,analysis_suspicious,analysis_undetected,analysis_unsupported,analysis_failure,comment,vt_link]
				csv_out.writerow(row)

def print_single_result(search_term):
	if error:
		pass
	else:
		hits_table = [['Search Term:', f'{search_term}']]
		hits_table += [['MD5:', f'{md5}']]
		hits_table += [['SHA1:', f'{sha1}']]
		hits_table += [['SHA256:', f'{sha256}']]
		hits_table += [['SSDeep:', f'{ssdeep}']]
		hits_table += [['Filetype:', f'{filetype}']]
		hits_table += [['Packers:', f'{packers}']]
		hits_table += [['Reputation:', f'{analysis_reputation}']]
		hits_table += [['Malicious:', f'{analysis_malicious}']]
		hits_table += [['Suspicious:', f'{analysis_suspicious}']]
		hits_table += [['Undetected:', f'{analysis_undetected}']]
		hits_table += [['Unsupported:', f'{analysis_unsupported}']]
		hits_table += [['Failure:', f'{analysis_failure}']]
		print('')
		print(tabulate(hits_table))
		print('')
		if comment != 'n/a':
			print('Comments: ')
			print('--------------------')
			c_count = 0
			for c in comment:
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
		check_hash(args.search_term,args.vt_api_key)
		print_single_result(args.search_term)
	elif args.file:
		with open(args.file) as f:
			hash_list = f.readlines()
			hash_list = [x.strip() for x in hash_list]
			print_multiple_results(args.outfile,hash_list,args.vt_api_key)
	elif args.upload_sample:
		upload_file(args.upload_sample,args.vt_api_key)
	elif args.download_link:
		download_file(args.download_link,args.vt_api_key)
	elif args.username:
		quota(args.username,args.vt_api_key)
	else:
		print((parser.format_help()))
		quit()

if __name__ == "__main__":
	main()
