```python
                _
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
      _
     / `/_      _/  /_/   _  _ _/__  _
    /_,//_//_//_/  / //_// //_'/ /_'/
                        Lacework Labs
```
### Dynamically generate and hunt with the Lacework Query Language (LQL)

Cloud-Hunter allows you to search for key data across the Lacework platform, with the advantage of crafting LQL queries for every search bring executed. This not only helps to find data quickly and easily, (even including content that isn't displayed in the console) but develop queries for ongoing monitoring as you scale the queries along with your organization's cloud security program.

Works alongside the Lacework CLI and the Lacework Labs project, LQL-Boss

* [Lacework CLI](https://github.com/lacework/go-sdk/wiki/CLI-Documentation)

* [LQL ATT&CK](https://github.com/lacework-dev/LQL-Attack)

* [LQL-Boss](https://github.com/lacework-dev/LQL-Boss)

* [Content](https://github.com/lacework-dev/lacework-content)

* [API Docs] https://<YOUR_SUBDOMAIN_HERE>.lacework.net/api/v2/docs

# Installation

Install and configure the Lacework GO-SDK (CLI) before proceeding:
```bash
# Download and install the Lacework GO-SDK
$ curl https://raw.githubusercontent.com/lacework/go-sdk/main/cli/install.sh | bash

# Configure to work with your organization
$ lacework configure

# Configuration data will be stored in the following file:
~/.lacework.toml
```
# Configuration

Make a note of the environments configured for use with the GO-SDK. The "default" setting will be used, so if you only have one environment configured, you can proceed on to the next steps.
```bash
# Install the python3 requirements:
$ pip3 install -r requirements.txt

# To run against environments other than the "default" configuration, declare using -environment:
$ ./cloud-hunter.py -environment MyEnvironment

# Display the help menu
$ ./cloud-hunter.py
```

# Query Generation

Leverage the included command line operators to develop queries for the Lacework Query Language (LQL) syntax. All commands below can be chained together for more targeted query development and hunting.

### Query Source
```bash
# Develop query for events matching an AWS event source
$ ./cloud-hunter.py -source <AWS Event Source>

# Example Event Sources:
iam.amazonaws.com, iam, kms, ec2, s3, etc...

# Search using the full text or partial matches
```

### Events
```bash
# Single Event
$ ./cloud-hunter.py -event <AWS Event Name>

# Example Events:
Client.DryRunOperation, ListAccessKeys, ListAttachedRolePolicies, etc.

# Multiple Events
$ ./cloud-hunter.py -events "'<AWS Event 1>', '<AWS Event 2>', '<AWS Event 3>'"

# Example Event Chaining:
$ ./cloud-hunter.py -events "'ListBackupVaults', 'ListBackupJobs', 'ListBackupPlans', 'ListCopyJobs', 'ListProtectedResources', 'ListRestoreJobs'"
```

### Event Type
```bash
# Generate a query for specific event type
$ ./cloud-hunter.py -type AwsConsoleSignIn
```

### Users
```bash
# Generate a query for specific user activity
$ ./cloud-hunter.py -username greg
```

### Source IP Address
```bash
# Generate a query for a source IP Address
$ ./cloud-hunter.py -ip 127.0.0.1
```

### User Agent String
```bash
# User Agent String by keyword
$ ./cloud-hunter.py -userAgent aws-cli

# Full user agent string - no quotes (") and escape the spaces
$ ./cloud-hunter.py -userAgent aws-cli/1.19.59\ Python/3.9.5\ Darwin/20.6.0\ botocore/1.20.59

# Note that LQL is case-sensitive
```

### DNS
```bash
# Search for queries to a specific domain
$ ./cloud-hunter.py -dns evil.site.com

# Search for a relative domain, such as any DNS query containing .ru
$ ./cloud-hunter.py -dns .ru
```

### Hostname
```bash
# Search for activities involving either a specific or relative hostname
$ ./cloud-hunter.py -hostname pwnedhost1234
```

### Filename
```bash
# Search for a specific file
$ ./cloud-hunter.py -filename potato.json

# Search for all files with a specified extension
$ ./cloud-hunter.py -filename .sh
```

### Command Line
```bash
# Search for any command line values
$ ./cloud-hunter.py -cmdline netcat
```

### Request Parameters
```bash
# Hunting by request parameters to look for potential injection attacks
$ ./cloud-hunter.py -reqParam +

# Multiple request parameters
$ ./cloud-hunter.py -reqParams "'+%','@%','=%','-%'"
```

### Errors
```bash
# Single Error
$ ./cloud-hunter.py -errorCode <AWS Error Name>

# Example Error:
AccessDenied, Client.UnauthorizedOperation, etc.

# Multiple Errors
$ ./cloud-hunter.py -errorCodes "'<AWS Error 1>', '<AWS Error 2>', '<AWS Error 3>'"

# Example Error Chaining:
$ ./cloud-hunter.py -errorCodes "'AccessDenied', 'Client.UnauthorizedOperation'"

```

### Access Denied Events
```bash
# Query for access denied events
# Toggle 'y' to list access denied events
# Toggle 'n' to set error type to 'null'
$ ./cloud-hunter.py -accessDenied y
```

### Query Chaining
```bash
# All parameters can be chained together to develop more complex and targeted queries
# Example:
$ ./cloud-hunter.py -source backup -events "'ListBackupVaults', 'ListProtectedResources'" -username bob -userAgent aws-cli -accessDenied y
```

### Special Queries
```bash
# Filter out certain values by adding '!' to each string
$ ./cloud-hunter.py -username '!greg' -accessDenied y

# Check if a certain parameter exists
cloud-hunter -username exists -errorCode Client.DryRunOperation
```

# Hunting

For any search term, append -r to execute the query and view results from the past 7-days of activity.

### Hunting by keywords
```bash
# For any query mentioned above, append -r to the command to execute the query and search

# Default timeframe is 7-days, this can be modified with the -t parameter
# Example search over 1-day:
$ ./cloud-hunter.py -username bob -t 1 -r

# Multiple parameters example:
$ ./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r

# Count the hits and do not display results to the screen
$ ./cloud-hunter.py -username bob -r -c
```

### Raw Query Hunting
```bash
# Execute any LQL query directly via the -hunt option
# Example:
$ ./cloud-hunter.py -hunt "LaceworkLabs_CloudHunter {SOURCE {CloudTrailRawEvents} FILTER { EVENT NOT IN ('DescribeTags', 'ListGrants') AND ERROR_CODE IN ('AccessDenied', 'Client.UnauthorizedOperation') } RETURN DISTINCT {INSERT_ID, INSERT_TIME, EVENT_TIME, EVENT}}"

# Hunting with a fully-formatted multi-line LQL rule:
$ ./cloud-hunter.py -hunt """LaceworkLabs_CloudHunter {
  source {
      LW_CFG_AWS_S3_GET_BUCKET_POLICY
  }
  return distinct {
    BATCH_START_TIME,
    BATCH_END_TIME,
    QUERY_START_TIME,
    QUERY_END_TIME,
    ARN,
    API_KEY,
    SERVICE,
    ACCOUNT_ID,
    ACCOUNT_ALIAS,
    RESOURCE_TYPE,
    RESOURCE_ID,
    RESOURCE_REGION,
    RESOURCE_CONFIG,
    RESOURCE_TAGS
  }
}"""

# Hunting with a LQL rule that is stored in a file:
$ ./cloud-hunter.py -hunt """$(cat /path/to/file.lql)"""

# Raw hunting can be combined with anytime, output, and counting options as well...

# Example hunting over a 30-day period (default is 7-days):
$ ./cloud-hunter.py -hunt "query" -t 30

# Example counting the hits:
$ ./cloud-hunter.py -hunt "query" -c

# Example with JSON output:
$ ./cloud-hunter.py -hunt "query" -j -o filename.json

# Example with CSV output:
$ ./cloud-hunter.py -hunt "query" -o filename.csv
```

### Exporting Data
```bash
# View the raw query data in JSON:
$ ./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -j

# View the raw query data in JSON and export to a file:
$ ./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -j -o filename.json

# Export the full query output to CSV:
$ ./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -o filename.csv

# Do not display output to screen but save the data to a CSV file.
$ ./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -o filename.csv -c
# Note - the count argument only works with CSV output.
```

# Modules

### VirusTotal Integration
```bash
# Leverage the ./modules/virustotal-hunt.sh bash script to hunt for files, IP's, or Domains and check results against VirusTotal

# Add your VirusTotal API key to the two virustotal scripts located in the ./modules/virustotal/ directory
# Replace the string [PLACE API KEY HERE] with your API key

# Running the script without options will display the help menu
$ ./virustotal-hunt.sh
#(             )
# `--(_   _)--'
#      Y-Y
#     /@@ \   Cloud-Hunter
#    /     \  >>---VT--->
#    `--'.  \             ,
#        |   `.__________/)
#           Lacework Labs
#
# ====================[ HELP ]====================
#
# Hunt via Filename or File Extension (.py):
#    $ ./virustotal-hunt -f "filename" -t "timeframe in days" -e "Lacework environment"
#
# Hunt via IP Address:
#    $ ./virustotal-hunt -i "ip address" -t "timeframe in days" -e "Lacework environment"
#
# Hunt via Domain:
#    $ ./virustotal-hunt -d "domain" -t "timeframe in days" -e "Lacework environment"
#
# Filename, Domain, or IP Address are required
# Timeframe and Environment are optional
#
# ==================================================

# Hunt for all files with a .py extension over a 180-day period:
$ ./virustotal-hunt.sh -f .py -t 180

# Hunt for suspicious DNS Requests over a single day:
$ ./virustotal-hunt.sh -d .ru -t 1

# Hunt for any activity where an IP address is present in the logs over a single day:
$ ./virustotal-hunt.sh -i exists -t 1
```

### Hunting at Scale
```bash
# Leverage the ./modules/scale-hunt.sh bash script to hunt across multiple organizations

# Hunt for activities and count the results:
./scale-hunt.sh -source backup -event ListBackupVaults -accessDenied y -t 10 -r -c

# This leverages all environments listed within your ~/.lacework.toml file to execute queries
```

# Author

Please feel free to reach out to Lacework Labs with ideas for improvement, queries, policies, issues, etc. 
```bash
greg.foss@lacework.net  --  Lacework Labs
```

# Changelog

Tracking major changes to the codebase
```bash
2/4/2022 - DNS Hunting
- Added DNS LQL parameters
- New VirusTotal DNS Hunting module

2/3/2022 - Version 1.0 Released
- Added Newly Available LQL Parameters:
    - hostname
    - filename
    - cmdline
- New VirusTotal Integration - Check files, IPs, and Domains against VirusTotal
- Various bug-fixes and code updates

9/1/2021 - Scale Hunting
- Added scale-hunt.sh to search across multiple Lacework environments

8/11/2021 - Beta Version 0.1 Released
```
