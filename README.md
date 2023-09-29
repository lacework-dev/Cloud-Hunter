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
### Dynamically create queries and hunt with the Lacework Query Language (LQL)

Cloud-Hunter allows you to search for key data across the Lacework platform, with the advantage of crafting LQL queries
for every search being executed. This not only helps to find data quickly and easily, (even including content that isn't
displayed in the console) but develop queries for ongoing monitoring as you scale the queries along with your
organization's cloud security program.

Works as a component of the Lacework CLI

* [Lacework CLI](https://docs.lacework.com/cli)

* [API Docs](https://docs.lacework.net/api/v2/docs/)

# Installation

Install and configure the Lacework CLI before proceeding:
```bash
# Download and install the Lacework CLI
$ curl https://raw.githubusercontent.com/lacework/go-sdk/main/cli/install.sh | bash

# Configure to work with your organization
$ lacework configure

# Configuration data will be stored in the following file:
~/.lacework.toml
```

Install `cloud-hunter` component:
```bash
$ lacework component install cloud-hunter
```

# Development Mode

Once the component is installed, you can enter development mode by running:
```
$ lacework component dev cloud-hunter --noninteractive
```

Clone this repository at `~/.config/lacework/components/cloud-hunter`
```
$ cd ~/.config/lacework/components/cloud-hunter
$ git init
$ git remote add origin https://github.com/afiune/cloud-hunter.git
$ git pull origin master
```

Build the component:
```
$ make build
```

Execute the component via `lacework cloud-hunter` ✨

# Configuration

Make a note of the environments configured for use with the GO-SDK. The "default" setting will be used, so if you only have one environment configured, you can proceed on to the next steps.
```bash
# To run against environments other than the "default" configuration, declare using --environment:
$ lacework cloud-hunter --environment MyEnvironment

# Display the help menu
$ lacework cloud-hunter
```

# Query Generation

Leverage the included command line operators to develop queries for the Lacework Query Language (LQL) syntax. All commands below can be chained together for more targeted query development and hunting.

### Query Source
```bash
# Hunt for events matching an AWS event source
$ lacework cloud-hunter --source <AWS Event Source>

# Example Event Sources:
iam.amazonaws.com, iam, kms, ec2, s3, etc...

# Search using the full text or partial matches
```

### Events
```bash
# Single Event
$ lacework cloud-hunter --event <AWS Event Name>

# Example Events:
Client.DryRunOperation, ListAccessKeys, ListAttachedRolePolicies, etc.

# Multiple Events
$ lacework cloud-hunter --events "'<AWS Event 1>', '<AWS Event 2>', '<AWS Event 3>'"

# Example Event Chaining:
$ lacework cloud-hunter --events "'ListBackupVaults', 'ListBackupJobs', 'ListBackupPlans', 'ListCopyJobs', 'ListProtectedResources', 'ListRestoreJobs'"
```

### Event Type
```bash
# Generate a query for specific event type
$ lacework cloud-hunter --type AwsConsoleSignIn
```

### Users
```bash
# Generate a query for specific user activity
$ lacework cloud-hunter --username greg
```

### Source IP Address
```bash
# Generate a query for a source IP Address
$ lacework cloud-hunter --ip 127.0.0.1
```

### User Agent String
```bash
# User Agent String by keyword
$ lacework cloud-hunter --userAgent aws-cli

# Full user agent string - no quotes (") and escape the spaces
$ lacework cloud-hunter --userAgent aws-cli/1.19.59\ Python/3.9.5\ Darwin/20.6.0\ botocore/1.20.59

# Note that LQL is case-sensitive
```

### DNS
```bash
# Search for queries to a specific domain
$ lacework cloud-hunter --dns evil.site.com

# Search for a relative domain, such as any DNS query containing .ru
$ lacework cloud-hunter --dns .ru
```

### Hostname
```bash
# Search for activities involving either a specific or relative hostname
$ lacework cloud-hunter --hostname pwnedhost1234
```

### Filename
```bash
# Search for a specific file
$ lacework cloud-hunter --filename potato.json

# Search for all files with a specified extension
$ lacework cloud-hunter --filename .sh
```

### Command Line
```bash
# Search for any command line values
$ lacework cloud-hunter --cmdline netcat
```

### Request Parameters
```bash
# Hunting by request parameters to look for potential injection attacks
$ lacework cloud-hunter --reqParam +

# Multiple request parameters
$ lacework cloud-hunter --reqParams "'+%','@%','=%','-%'"
```

### Errors
```bash
# Single Error
$ lacework cloud-hunter --errorCode <AWS Error Name>

# Example Error:
AccessDenied, Client.UnauthorizedOperation, etc.

# Multiple Errors
$ lacework cloud-hunter --errorCodes "'<AWS Error 1>', '<AWS Error 2>', '<AWS Error 3>'"

# Example Error Chaining:
$ lacework cloud-hunter --errorCodes "'AccessDenied', 'Client.UnauthorizedOperation'"

```

### Access Denied Events
```bash
# Query for access denied events
# Toggle 'y' to list access denied events
# Toggle 'n' to set error type to 'null'
$ lacework cloud-hunter --accessDenied y
```

### Query Chaining
```bash
# All parameters can be chained together to develop more complex and targeted queries
# Example:
$ lacework cloud-hunter --source backup --events "'ListBackupVaults', 'ListProtectedResources'" --username bob --userAgent aws-cli --accessDenied y
```

### Special Queries
```bash
# Filter out certain values by adding '!' to each string
$ lacework cloud-hunter --username '!greg' --accessDenied y

# Check if a certain parameter exists
$ /cloud-hunter.py --username exists --errorCode Client.DryRunOperation

# To view the generated LQL query, append -j to the command. The will be idisplayed but will not execute
$ /cloud-hunter.py --username exists --errorCode Client.DryRunOperation -j
```

# Hunting

For any search term, append to execute the query and view results from the past 7-days of activity.

### Hunting by keywords
```bash
# Default timeframe is 7-days, this can be modified with the -t parameter
# Example search over 1-day:
$ lacework cloud-hunter --username bob -t 1

# Multiple parameters example:
$ lacework cloud-hunter --source backup --event ListBackupVaults --username bob --userAgent aws-cli --accessDenied y

# Count the hits and do not display results to the screen
$ lacework cloud-hunter --username bob -c
```

### File-Based Rule Hunting

```bash
# Hunting with a LQL rule that is stored in a file:
$ lacework cloud-hunter -y /path/to/file.yaml

# YAML format-files are preferred
# Raw LQL query text-files will work as well
````

### Raw Query Hunting
```bash
# Execute any LQL query directly via the -hunt option
# Example:
$ lacework cloud-hunter --hunt "LaceworkLabs_CloudHunter {SOURCE {CloudTrailRawEvents} FILTER { EVENT NOT IN ('DescribeTags', 'ListGrants') AND ERROR_CODE IN ('AccessDenied', 'Client.UnauthorizedOperation') } RETURN DISTINCT {INSERT_ID, INSERT_TIME, EVENT_TIME, EVENT}}"

# Hunting with a fully-formatted multi-line LQL rule:
$ lacework cloud-hunter --hunt """LaceworkLabs_CloudHunter {
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

# Raw hunting can be combined with any time, output, and counting options as well...

# Example hunting over a 30-day period (default is 7-days):
$ lacework cloud-hunter --hunt "query" -t 30

# Example counting the hits:
$ lacework cloud-hunter --hunt "query" -c

# Example with JSON output:
$ lacework cloud-hunter --hunt "query" -j -o filename.json

# Example with CSV output:
$ lacework cloud-hunter --hunt "query" -o filename.csv
```

### Exporting Data
```bash
# View the raw query data in JSON:
$ lacework cloud-hunter --source backup --event ListBackupVaults --username bob --userAgent aws-cli --accessDenied y -j

# View the raw query data in JSON and export to a file:
$ lacework cloud-hunter --source backup --event ListBackupVaults --username bob --userAgent aws-cli --accessDenied y -j -o filename.json

# Export the full query output to CSV:
$ lacework cloud-hunter --source backup --event ListBackupVaults --username bob --userAgent aws-cli --accessDenied y -o filename.csv

# Do not display output to screen but save the data to a CSV file.
$ lacework cloud-hunter --source backup --event ListBackupVaults --username bob --userAgent aws-cli --accessDenied y -o filename.csv -c
# Note - the count argument only works with CSV output.
```

# [Modules](./modules/)

Modules extend the Cloud-Hunter platform and are located in the ./modules/ directory

### [Hunting at Scale](./modules#hunting-at-scale)
```bash
                .   Cloud-Hunter   |      *
     *             *              -O-          .
           .             *         |     ,
          .---.
    =   _/__~0_\_     .  *  Scale-Hunt   o    ,
   = = (_________)             .
                   .                        *
         *               - ) -       *
                . Lacework Labs .

$ ./modules/scale-hunt.sh
# Hunt across multiple Lacework Tenants at once
```

### [VirusTotal](./modules#virustotal-integration)
```bash
(             )
 `--(_   _)--'
      Y-Y
     /@@ \\   Cloud-Hunter
    /     \\  >>---VT--->
    \`--'.  \\             ,
        |   `.__________/)
           Lacework Labs

$ ./modules/virustotal-hunt.sh
# Hunt for files, IP's, or Domains and check results against VirusTotal
```

### [Greynoise](./modules#greynoise-integration)
```bash

   /^^^^   
 /^    /^^ 
/^^            Greynoise
/^^            IP-Hunter
/^^   /^^^^
 /^^    /^ 
  /^^^^^   
          Lacework Labs

$ ./modules/greynoise-hunt.sh
# Hunt for IP's and check results against Greynoise
```

Module core-scripts are stored within the ./modules/scripts/ directory

# Author

Please feel free to reach out to Lacework Labs with ideas for improvement, queries, policies, issues, etc. 
```bash
cloud-hunter@lacework.net
```
Contribute to the framework by opening a pull request

# Changelog

Tracking major changes to the codebase
```bash
10/01/2023 - CDK Component Release

9/19/2022 - Public Release

4/4/2022 - NoCase and Sub Accounts
- Added the ability to hunt across sub-accounts
- Added ignore casing for fuzzy searches
- Improved query and result formatting

2/14/2022 - New Module
- Added a new Greynoise IP inspection module
- Made query display optional and cleaned up output
- Added YAML file support

2/7/2022 - JSON Configuration
- Updated modules to use a configuration file
- New LQL Parameters:
    - OS, Filetype

2/4/2022 - DNS Hunting
- Added DNS LQL parameters
- New VirusTotal DNS Hunting module

2/3/2022 - Version 1.0 - Internal Release
- Added New LQL Parameters:
    - CMDline, Hostname, Filename
- New VirusTotal Integration - Check files and IPs against VirusTotal
- Various bug-fixes and code updates

9/1/2021 - Scale Hunting
- Added scale-hunt.sh to search across multiple Lacework environments

8/11/2021 - Beta Version 0.1 - Internal Release
```
