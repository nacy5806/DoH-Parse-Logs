## Description
Uses the [DoHClient module](https://github.com/vintagecircuit/DoH-Client-Module/tree/main) to process network logs and output data about them to a .csv file.

**Note**: The DoHClient module currently only supports IPv4 addresses. IPv6 addresses will be ignored. 
## Expected Network Log File Format
A .csv file of network logs with the header msg_original,TimeGenerated [Central Time (US and Canada)],Protocol,SourceIP,SourcePort,Target,TargetPort,URL,Action,NatDestination,OperationName,ThreatIntel,IDSSignatureID,IDSSignatureDescription,IDSPriority,IDSClassification,Policy,RuleCollectionGroup,RuleCollection,Rule,WebCategory.
## Dependencies
- Python (>= 3.6)
- `requests`
- `ipaddress`

**Note**: `doh_cache` and `doh_logger` are custom modules; ensure they are included in your project directory.

## Usage
From the command line, write 

"python3 parse_network_logs.py <log_file.csv> <successful_lookups.csv> <failed_lookups.csv>", OR 

"python3 parse_network_logs.py <log_directory> <successful_lookups.csv> <failed_lookups.csv>."




