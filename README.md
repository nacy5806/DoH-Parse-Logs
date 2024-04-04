## Description
Uses the [DoHClient module](https://github.com/vintagecircuit/DoH-Client-Module/tree/main) to gather data about network logs; specifically, given a .csv file of network logs with the header
            msg_original,TimeGenerated [Central Time (US and Canada)],Protocol,SourceIP,SourcePort,Target,TargetPort,URL,Action,NatDestination,OperationName,ThreatIntel,IDSSignatureID,IDSSignatureDescription,IDSPriority,IDSClassification,Policy,RuleCollectionGroup,RuleCollection,Rule,WebCategory,
        **make one csv file containing a list of distinct domain / target port pairs, along with their frequency, and make a different csv file containing the list of addresses that the domain lookup failed for.**
        
**Note**: The DoHClient module currently only supports IPv4 addresses. IPv6 addresses will be ignored. 

## Dependencies
- Python (>= 3.6)
- `requests`
- `ipaddress`

**Note**: `doh_cache` and `doh_logger` are custom modules; ensure they are included in your project directory.

## Usage
From the command line, write "python3 parse_network_logs.py <log_file.csv> <successful_lookups.csv> <failed_lookups.csv>". 




