from DoHClient import DoHClient
import sys
import os


def usage():
    """ Print usage info and exit. """
    print("Usage: python3 " + sys.argv[0] + " <log_file.csv | log_directory> <successful_lookups.csv> <failed_lookups.csv>")
    exit()


class ReverseDNSAnalyzer:
    def __init__(self):
        self.num_successful_lookups = 0
        self.num_failed_lookups = 0
        self.rdns_client = DoHClient()

        self.domain_port_frequency = dict()
        self.set_failed_lookups = set()

    def _read_analyze_file(self, logfile):
        """ Expects logfile to be an open file object in the format specified in ReverseDNSAnalyzer.analyze().
        """
        logfile.readline()  # move past the header row

        # move through the file, line by line, looking at each entry
        log_entry = logfile.readline()
        while log_entry != "":
            log_entry = log_entry.strip().split(',')
            if len(log_entry) < 9:
                log_entry = logfile.readline()
                continue

            # we only care about Target, TargetPort, and Action, which are indices 5, 6, and 8 (0-indexed) in the spreadsheet
            target_ip_address = log_entry[5].strip("\"")
            target_port = log_entry[6]
            action = log_entry[8]

            if action == "Allow":
                hostname = self.rdns_client.reverse_lookup(target_ip_address)
                if hostname is not None:
                    self.num_successful_lookups += 1
                    # we mainly care about the last 2 labels in the hostname; get rid of the rest
                    domain = ".".join(hostname.split(".")[-3:-1])
                    if (domain, target_port) in self.domain_port_frequency:
                        self.domain_port_frequency[(domain, target_port)] += 1
                    else:
                        self.domain_port_frequency[(domain, target_port)] = 1
                else:
                    self.num_failed_lookups += 1
                    self.set_failed_lookups.add(target_ip_address)

            log_entry = logfile.readline()

    def analyze(self, file_or_dir):
        """ Given a .csv file (or a directory containing .csv files) of network logs with the header
                msg_original,TimeGenerated [Central Time (US and Canada)],Protocol,SourceIP,SourcePort,Target,TargetPort,URL,Action,NatDestination,OperationName,ThreatIntel,IDSSignatureID,IDSSignatureDescription,IDSPriority,IDSClassification,Policy,RuleCollectionGroup,RuleCollection,Rule,WebCategory,
            add the distinct domain / target port pairs to domain_port_frequency, along with their frequency.
            Also add the IP addresses that RDNS failed for to set_failed_lookups.
        """
        if os.path.isdir(file_or_dir):
            for file in os.listdir(file_or_dir):
                print("Processing " + file + " in " + file_or_dir + "...")
                logfile = open(file_or_dir + "/" + file, "r", encoding="utf8")
                self._read_analyze_file(logfile)
                logfile.close()
                print("Finished processing " + file + ".")
        else:
            print("Processing " + file_or_dir + "...")
            logfile = open(file_or_dir, "r", encoding="utf8")
            self._read_analyze_file(logfile)
            logfile.close()
            print("Finished processing " + file_or_dir + ".")

    def write_results(self, successful_lookups_file, failed_lookups_file):
        """ Writes the outcome (the domain port frequency and the ip addresses of failed lookups) to
            the supplied file objects. """
        successful_lookups_file.write("Domain,Port,Number of Occurrences\n")
        for (domain, port) in sorted(self.domain_port_frequency.keys()):
            successful_lookups_file.write(domain + "," + port + "," + str(self.domain_port_frequency[(domain, port)]) + "\n")

        failed_lookups_file.write("Failed Lookups\n")
        for failed_lookup in self.set_failed_lookups:
            failed_lookups_file.write(failed_lookup + "\n")

        if self.num_failed_lookups + self.num_successful_lookups > 0:
            print("\nSuccessfully wrote to specified files.\nReverse lookup failure rate: {:.2f}%".format(
            100 * self.num_failed_lookups / (self.num_failed_lookups + self.num_successful_lookups)))
        else:
            print("\nSuccessfully wrote to specified files.\nNo logs were processed.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    elif len(sys.argv) != 4:
        print("ERROR: Incorrect number of arguments.")
        usage()
    elif not os.path.exists(sys.argv[1]):
        print("ERROR: Input file or directory doesn't exist.")
        usage()
    elif sys.argv[3] == sys.argv[1] or sys.argv[2] == sys.argv[1]:
        print("ERROR: One of the output files is set to be the input file, which would overwrite the log file.")
        usage()
    elif os.path.isdir(sys.argv[1]) and len(os.listdir(sys.argv[1])) == 0:
        print("ERROR: Supplied directory is empty.")
        usage()

    successful_lookups = open(sys.argv[2], "w+", encoding="utf8")
    failed_lookups = open(sys.argv[3], "w+", encoding="utf8")

    rdnsa = ReverseDNSAnalyzer()
    rdnsa.analyze(sys.argv[1])
    rdnsa.write_results(successful_lookups, failed_lookups)

    successful_lookups.close()
    failed_lookups.close()
