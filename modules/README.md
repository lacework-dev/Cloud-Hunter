# Cloud-Hunter Modules

Modules extend the Cloud-Hunter platform and configuration options are handled by ./modules/config.json

```bash
# Copy example-config.json to config.json and edit the options to refelct your settings
$ cp ./modules/config_example.json ./modules/config.json; vim ./modules/config.json
```
```json
{
    "primary_lacework_tenant_name": "default",
    "cloud_hunter_script_location": "/full/path/to/cloud-hunter.py",
    "virustotal_api_key": "KEY",
    "greynoise_api_key": "KEY"
}
```
```bash
# These scripts leverage the environments listed within your ~/.lacework.toml file
```

### Hunting at Scale
```bash
# ============================================================
                .   Cloud-Hunter   |      *
     *             *              -O-          .
           .             *         |     ,
          .---.
    =   _/__~0_\_     .  *  Scale-Hunt   o    ,
   = = (_________)             .
                   .                        *
         *               - ) -       *
                . Lacework Labs .

# Hunt across multiple Lacework Tenants at once

# Run the script without options to view the help menu
$ ./scale-hunt.sh

# scale-hunt.sh takes the same arguments as cloud-hunter.py
# run cloud-hunter.py to obtain a list of available options

# Hunt for activities and count the results:
$ ./scale-hunt.sh -source backup -event ListBackupVaults -accessDenied y -t 10 -r -c
# ============================================================
```

### VirusTotal Integration
```bash
# ============================================================
(             )
 `--(_   _)--'
      Y-Y
     /@@ \\   Cloud-Hunter
    /     \\  >>---VT--->
    \`--'.  \\             ,
        |   `.__________/)
           Lacework Labs

# Hunt for files, IP's, or Domains and check results against VirusTotal

# Run the script without options to view the help menu
$ ./virustotal-hunt.sh

# Hunt for all files of a specific type of the default (7-day) time period:
$ ./virustotal-hunt.sh -x python

# Hunt for all files matching a keyword over a 180-day period:
$ ./virustotal-hunt.sh -f xmrig -t 180

# Hunt for suspicious DNS Requests over a single day:
$ ./virustotal-hunt.sh -d .ru -t 1

# Hunt for any activity where an IP address is present in the logs over a single day:
$ ./virustotal-hunt.sh -i exists -t 1

#  [ ! ] Filename, Domain, or IP Address are required
#  [ - ] Timeframe and Environment are optional
# ============================================================
```

### Greynoise Integration
```bash
# ============================================================
   /^^^^   
 /^    /^^ 
/^^            Greynoise
/^^            IP-Hunter
/^^   /^^^^
 /^^    /^ 
  /^^^^^   
          Lacework Labs

# Hunt for IP's and check results against Greynoise

# Run the script without options to view the help menu
$ ./greynoise-hunt.sh

# Hunt for any activity where an IP address is present in the logs over a single day:
$ ./greynoise-hunt.sh -i exists -t 1

#  [ ! ] IP Address is required
#  [ - ] Timeframe and Environment are optional
# ============================================================
```

# Module Authors

Contribute modules by opening a pull request
```bash
greg.foss@lacework.net
- Scale-Hunt
- Cloud-Hunter VT
- Greynoise IP-Hunter

```
Please feel free to reach out to Lacework Labs with ideas for improvement, queries, policies, issues, etc.