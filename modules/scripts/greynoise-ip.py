#!/usr/bin/env python3

# Greynoise Community Edition - IP Check
# Lacework Labs
# v0.1 - February, 2022
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
import pandas as pd
from tabulate import tabulate

def parse_all_things():
  parser = argparse.ArgumentParser(description = 'Analyze IP\'s with the Greynoise API')
  parser.add_argument('-a', '--ip', help = 'Analyze a single IP', dest = 'ip_address')
  parser.add_argument('-f', '--file', help = 'Analyze a list of IP\'s stored within a file', dest = 'file')
  parser.add_argument('-o', '--outfile', help = 'Output the results of multi-IP analysis, default value -> greynoise_ips.csv', default = 'greynoise_ips.csv', dest = 'outfile')
  parser.add_argument('-k', '--api', help = 'Greynoise API Key', default = 'api-key', dest = 'key')
  return parser

def query(ip_address,key):
  url = f"https://api.greynoise.io/v3/community/{ip_address}"
  headers = {
    'key': f'{key}'
  }
  response = requests.request("GET", url, headers=headers)
  response = json.loads(response.text)
  ip_df = pd.DataFrame(response, index=[0])
  le_table = []
  for col in ip_df:
    val = ip_df[col]
    le_table += [[col, val.to_string(index=False)]]
  print()
  print("IP Details:")
  print(tabulate(le_table))
  print()

def multi_query(outfile,ip_list,key):
  print()
  print('Printing data out to %s...' % outfile)
  print('IP | Noise | Riot | Classification | Name | Link | Last Seen | Message')
  table_header = ['IP','Noise','Riot','Classification','Name','Link','Last Seen','Message']
  with open(outfile,'a') as out:
    csv_out=csv.writer(out)
    csv_out.writerow(['IP','Noise','Riot','Classification','Name','Link','Last Seen','Message'])
    for ip_address in ip_list:
      url = f"https://api.greynoise.io/v3/community/{ip_address}"
      headers = {
        'key': f'{key}'
      }
      response = requests.request("GET", url, headers=headers)
      response = json.loads(response.text)
      ip = response['ip']
      noise = response['noise']
      riot = response['riot']
      message = response['message']
      try:
        classification = response['classification']
      except:
        classification = 'n/a'
      try:
        name = response['name']
      except:
        name = 'n/a'
      try:
        link = response['link']
      except:
        link = 'n/a'
      try:
        last_seen = response['last_seen']
      except:
        last_seen = 'n/a'
      print(f'{ip} | {noise} | {riot} | {classification} | {name} | {link} | {last_seen} | {message}')
      row = [ip,noise,riot,classification,name,link,last_seen,message]
      csv_out.writerow(row)
  print()

def main():
  parser = parse_all_things()
  args = parser.parse_args()
  
  if args.ip_address:
    query(args.ip_address,args.key)
  elif args.file:
    with open(args.file) as f:
      ip_list = f.readlines()
      ip_list = [x.strip() for x in ip_list]
      multi_query(args.outfile,ip_list,args.key)
  else:
    print((parser.format_help()))
    quit()

if __name__ == "__main__":
  main()