# query_crowdstrike
test query for crowdstrike API:<br>
* look up a single host by hostname `--hostname HOST`
* look up vulnerabilities by hostname `--hostname HOST --list-vulns`
* look up any host(s) by FQL filter `--filter`
* list custom RTR scripts' details

# usage
```
$ python main.py --help
usage: main.py [-h] --client-id CLIENT_ID --client-secret CLIENT_SECRET [--hostname HOSTNAME] [--filter FILTER] [--domain DOMAIN] [--proxies PROXIES]
               [--list-vulns] [--list-scripts]

options:
  -h, --help                     show this help message and exit
  --client-id CLIENT_ID          The client_id of the API key
  --client-secret CLIENT_SECRET  The API key
  --hostname HOSTNAME            The hostname to query for
  --filter FILTER                The query filter to use to filter the agent ID query results
  --domain DOMAIN                The FQDN for your Crowdstrike account's API (not full URL)
  --proxies PROXIES              JSON structure specifying 'http' and 'https' proxy URLs
  --list-vulns                   Get vulnerabilities for the specified host
  --list-scripts                 List RTR custom scripts details
```


# example: look up host with vulnerability details
`python3 main.py --domain api.crowdstrike.com --client-id blah --client-secret blah --hostname abc123 --list-vulns`

# example: list all custom scripts
`python3 main.py --domain api.crowdstrike.com --client-id blah --client-secret blah --list-scripts`

