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
### Dynamically generate and hunt with the Lacework Query Language (LQL) quickly and efficiently

Cloud-Hunter allows you to search for key data across the Lacework platform, with the advantage of crafting LQL queries for every search bring executed. This not only helps to find data quickly and easily, (even including content that isn't displayed in the console) but develop queries for ongoing monitoring as you scale the queries along with your organization's cloud security program.

Works alongside the Lacework CLI and the Lacework Labs project, LQL-Boss

[Lacework CLI] https://github.com/lacework/go-sdk/wiki/CLI-Documentation

[LQL-Boss] https://github.com/lacework-dev/LQL-Boss

[Content]  https://github.com/lacework-dev/lacework-content

[API Docs] https://(environment).lacework.net/api/v2/docs

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
./cloud-hunter.py -source <AWS Event Source>

# Example Event Sources:
iam.amazonaws.com, iam, kms, ec2, s3, etc...

# Search using the full text or partial matches
```

### Events
```bash
# Single Event
./cloud-hunter.py -event <AWS Event Name>

# Example Events:
Client.DryRunOperation, ListAccessKeys, ListAttachedRolePolicies, etc.

# Multiple Events
./cloud-hunter.py -events "'<AWS Event 1>', '<AWS Event 2>', '<AWS Event 3>'"

# Example Event Chaining:
./cloud-hunter.py -events "'ListBackupVaults', 'ListBackupJobs', 'ListBackupPlans', 'ListCopyJobs', 'ListProtectedResources', 'ListRestoreJobs'"
```

### Users
```bash
# Generate a query for specific user activity
./cloud-hunter.py -username greg
```

### Source IP Address
```bash
# Generate a query for a source IP Address
./cloud-hunter.py -ip 127.0.0.1
```

### User Agent String
```bash
# User Agent String by keyword
./cloud-hunter.py -userAgent aws-cli

# Full user agent string - no quotes (") and escape the spaces
./cloud-hunter.py -userAgent aws-cli/1.19.59\ Python/3.9.5\ Darwin/20.6.0\ botocore/1.20.59

# Note that LQL is case-sensitive
```

### Errors
```bash
# Single Error
./cloud-hunter.py -errorCode <AWS Error Name>

# Example Error:
AccessDenied, Client.UnauthorizedOperation, etc.

# Multiple Errors
./cloud-hunter.py -errorCodes "'<AWS Error 1>', '<AWS Error 2>', '<AWS Error 3>'"

# Example Error Chaining:
./cloud-hunter.py -errorCodes "'AccessDenied', 'Client.UnauthorizedOperation'"

```

### Access Denied Events
```bash
# Query for access denied events
# Toggle 'y' to list access denied events
# Toggle 'n' to set error type to 'null'
./cloud-hunter.py -accessDenied y
```

### Query Chaining
```bash
# All parameters can be chained together to develop more complex and targeted queries
# Example:
./cloud-hunter.py -source backup -events "'ListBackupVaults', 'ListProtectedResources'" -username bob -userAgent aws-cli -accessDenied y
```

### Special Queries
```bash
# Filter out certain values by adding '!' to each string
./cloud-hunter.py -username '!greg' -accessDenied y

# Check if a certain parameter exists
cloud-hunter -username exists -errorCode Client.DryRunOperation
```

# Hunting

For any search term, append -r to execute the query and view results from the past 7-days of activity.

### Hunting by keywords
```bash
# For any query mentioned above, append -r to the command to execute the query and search

# Default timeframe is 7-days, this can be modified with the -timeframe parameter
# Example search over 1-day:
./cloud-hunter.py -username bob -timeframe 1 -r

# Multiple parameters example:
./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r
```

### Raw Query Hunting
```bash
# Execute any LQL query directly via the -hunt option
# Example:
./cloud-hunter.py -query "LaceworkLabs_CloudHunter {SOURCE {CloudTrailRawEvents} FILTER { EVENT NOT IN ('DescribeTags', 'ListGrants') AND ERROR_CODE IN ('AccessDenied', 'Client.UnauthorizedOperation') } RETURN DISTINCT {INSERT_ID, INSERT_TIME, EVENT_TIME, EVENT}}"
```

### Exporting Data
```bash
# View the raw query data in JSON:
./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -j

# View the raw query data in JSON and export to a file:
./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -j -o filename.json

# Export the full query output to CSV:
./cloud-hunter.py -source backup -event ListBackupVaults -username bob -userAgent aws-cli -accessDenied y -r -o filename.csv
```

# Author

Please feel free to reach out to Lacework Labs with ideas for improvement, queries, policies, issues, etc. 
```bash
greg.foss@lacework.net  --  Lacework Labs
```