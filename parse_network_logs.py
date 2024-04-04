from DoHClient import DoHClient
import sys


def usage():
    """ Print usage info and exit. """
    print("Usage: python3 " + sys.argv[0] + " <log_file.csv> <successful_lookups.csv> <failed_lookups.csv>")
    exit()


def read_lookup_write(log_name, successful_lookup_name, failed_lookup_name):
    """ Given a .csv file of network logs with the header
            msg_original,TimeGenerated [Central Time (US and Canada)],Protocol,SourceIP,SourcePort,Target,TargetPort,URL,Action,NatDestination,OperationName,ThreatIntel,IDSSignatureID,IDSSignatureDescription,IDSPriority,IDSClassification,Policy,RuleCollectionGroup,RuleCollection,Rule,WebCategory,
        make a file containing a list of distinct domain / target port pairs, along with their frequency.
        Also make a file containing the list of addresses that the domain lookup failed for.
    """
    logfile = open(log_name, "r", encoding="utf8")
    successful_lookups = open(successful_lookup_name, "w+", encoding="utf8")
    failed_lookups = open(failed_lookup_name, "w+", encoding="utf8")

    num_successful_lookups = 0
    num_failed_lookups = 0

    client = DoHClient()  # the reverse lookup client
    domain_port_frequency = dict()  # maps (domain, port) to the frequency it appears in the log file
    logfile.readline()  # move past the header row

    # move through the file, line by line, looking at each entry
    log_entry = logfile.readline()
    while log_entry != "":
        log_entry = log_entry.strip().split(',')
        if len(log_entry) < 9:
            log_entry = logfile.readline()
            continue

        # we only care about Target, TargetPort, and Action, which are indices 5, 6, and 8 (0-indexed) in the spreadsheet
        target_ip_address = log_entry[5]
        target_port = log_entry[6]
        action = log_entry[8]

        if action == "Allow":
            hostname = client.reverse_lookup(target_ip_address)
            if hostname is not None:
                num_successful_lookups += 1
                # we mainly care about the last 2 labels in the hostname; get rid of the rest
                domain = ".".join(hostname.split(".")[-3:-1])
                if (domain, target_port) in domain_port_frequency:
                    domain_port_frequency[(domain, target_port)] += 1
                else:
                    domain_port_frequency[(domain, target_port)] = 1
            else:
                num_failed_lookups += 1
                failed_lookups.write(target_ip_address + "\n")

        log_entry = logfile.readline()

    successful_lookups.write("Domain,Port,Number of Occurrences\n")
    for (domain, port) in sorted(domain_port_frequency.keys()):
        successful_lookups.write(domain + "," + port + "," + str(domain_port_frequency[(domain, port)]) + "\n")

    logfile.close()
    successful_lookups.close()
    failed_lookups.close()

    print("Successfully wrote to specified files.\nReverse lookup failure rate: {:.2f}%".format(
        100 * num_failed_lookups / (num_successful_lookups + num_failed_lookups)))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    elif len(sys.argv) != 4:
        print("ERROR: Incorrect number of arguments.")
        usage()
    elif sys.argv[3] == sys.argv[1] or sys.argv[2] == sys.argv[1]:
        print("ERROR: One of the output files is set to be the input file, which would overwrite the log file.")
        usage()

    read_lookup_write(sys.argv[1], sys.argv[2], sys.argv[3])


