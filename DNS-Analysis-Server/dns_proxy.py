from scapy.all import *
from random import randint
import json
import time
import re
import string
import random
import os

# scapy stuff for sniffing and sending packets
BPF_FILTER = f"dst host 10.100.100.3 and dst port 53"
conf.L3socket
conf.L3socket = L3RawSocket

# Dictionary of already queried domains and used response types (0 as txid, random port, etc. ...)
queried_domains = {}

# Dictionary of domain mappings to use
domain_mappings = {}
domain_mappings_file = os.environ.get("MAPPING_FILE",None)
if domain_mappings_file and os.path.exists(domain_mappings_file):
    domain_mappings = json.loads(open(domain_mappings_file,"r").read())

# activated methods (other methods can be added by appending them to this list)
methods = json.loads(os.environ.get("METHODS",'["ip_fragmentation", "recursive_delegation", "edns_removal", "empty_edns"]'))

# standard encoding
encoding = "utf-8"

# logs
dns_log_file = "/data/dns_log.txt"
dns_dump_file = "/data/dns_dump.pcap"

# logging
logging = True
logging_mode = os.environ.get("LOGGING", "MINIMAL")

# analysis domain used for testing
analysis_domain = os.environ.get("NS_DOMAIN","domain.example")

authoritative_domain = analysis_domain
authoritative_domain_dot = analysis_domain + "."
dot_authoritative_domain = "." + analysis_domain
dot_authoritative_domain_dot = "." + analysis_domain + "."

# IPs of the used namerserver (may be the same)
analysis_domain_ip = "10.100.100.3"

# Nameserver prefixes used
nameserver_prefixes = ["ns1", "ns2"]

# Prefix for the mail mx record
mailexchange_prefix = "mail"

# TTLs for returned DNS responses
ttl = 604800
ttl_short = 5
ttl_medium = 3600
ttl_long = 604800

# Number of records to add when using recursive delegation
number_of_records_to_add_rd = 10

# gets the used packet protocol
def get_packet_protocol(pkt):
    if pkt.haslayer(UDP) == 1:
        return UDP
    else:
        return TCP


# extracts arbitrary information from a packet
def extract_query_packet_data(pkt):
    layer_4_protocol = get_packet_protocol(pkt)
    data = {}
    data["time"] = time.time()
    data["source_ip"] = pkt[IP].src
    data["destination_ip"] = pkt[IP].dst
    data["source_port"] = pkt[layer_4_protocol].sport
    data["destination_port"] = pkt[layer_4_protocol].dport
    if layer_4_protocol == UDP:
        data["layer_4_protocol"] = "UDP"
    else:
        data["layer_4_protocol"] = "TCP"

    return data


# extracts DNS information from a packet
def extract_dns_query_packet_data(pkt):
    layer_4_protocol = get_packet_protocol(pkt)
    data = {}
    query_name = pkt[DNS].qd.qname
    query_name = query_name.decode("UTF-8")
    data["query_name"] = query_name
    data["domain"] = query_name.lower().split(dot_authoritative_domain)[0]
    data["type"] = pkt[DNS].qd.qtype
    data["resolver_ip"] = pkt[IP].src
    data["source_port"] = pkt[layer_4_protocol].sport
    data["transaction_id"] = pkt[DNS].id
    data["application_identifier"] = "0"
    if re.search("[0-9]{10}", query_name) != None:
        data["application_identifier"] = re.search("[0-9]{10}", query_name).group(0)

    if data["application_identifier"] in domain_mappings.keys():
        data["domain_name"] = domain_mappings[data["application_identifier"]]

    if pkt[DNS].arcount == 1 and pkt[DNS].ar[0].type == 41:
        data["edns"] = True
        if bin(pkt[DNS].ar[0].z)[2:][0] != "1":
            data["dnssec"] = False
        else:
            data["dnssec"] = True

        data["edns_size"] = pkt[DNS].ar[0].rclass

        if len(pkt[DNS].ar[0].rdata) != 0:
            if pkt[DNS].ar[0].rdata[0].optcode != 10:
                data["dns_cookies"] = False
            else:
                data["dns_cookies"] = True
        else:
            data["dns_cookies"] = False

    else:
        data["edns"] = False
        data["dnssec"] = False
        data["edns_size"] = False
        data["dns_cookies"] = False

    return data


# function returning a dictionary of packet information to log
def get_packet_data(pkt):

    data = {}
    tmp_dns_data = extract_dns_query_packet_data(pkt)
    if logging_mode == "FULL":
        data["raw_packet"] = str(pkt)
    data["metadata"] = extract_query_packet_data(pkt)
    data["dns_metadata"] = tmp_dns_data

    return data


# remove all answers from the BIND9 server that are not in the question section and are no OPT records
def strip_dns_packet(pkt, leave_ns_section=False):

    # remove answer an ns sections (they get replaced with identifiable values)
    pkt[DNS].an = None
    pkt[DNS].ancount = 0
    if leave_ns_section == False:
        pkt[DNS].ns = None
        pkt[DNS].nscount = 0

    # search for OPT record and set it as response (None if no OPT record is found)
    opt_record = None
    for arcount in range(pkt[DNS].arcount):
        if pkt[DNS].ar[arcount].type == 41:
            opt_record = pkt[DNS].ar[arcount]

    pkt[DNS].ar = opt_record

    if opt_record == None:
        pkt[DNS].arcount = 0
    else:
        pkt[DNS].arcount = 1

    return pkt


# manipulate the global response packet based on different test methods
def craft_analysis_packet(global_request, global_response):

    # Get response packet data for modification
    global_request_dns_data = extract_dns_query_packet_data(global_request)
    global_request_metadata = extract_query_packet_data(global_request)

    ### DO MODIFICATIONS TO THE PACKET HERE ###

    # get query name of the current request. The lower() function is required to group requests that use 0x20 encoding
    tmp_name = global_request_dns_data["query_name"].lower()

    # get domain of the current request. The lower() function is required to group requests that use 0x20 encoding
    tmp_domain = global_request_dns_data["domain"].lower()

    # get application identifier
    tmp_application_identifier = global_request_dns_data["application_identifier"]

    # Get the type of the record requested. A == 1 and MX == 15. A full list can be found here: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    tmp_type = global_request_dns_data["type"]

    # get protocol of the current request
    tmp_layer_4_protocol = global_request_metadata["layer_4_protocol"]

    # create domain in queried_domains if it doesn't exist yet
    if tmp_domain not in queried_domains.keys():
        queried_domains[tmp_domain] = {}

        # if the tmp domain matches the test format, set the method accordingly
        # test format used: [User]@[2 digits version number][2 digits method number][6 digits domain number].[analysis domain]
        if re.match("^[0-9]{10}$", tmp_application_identifier) != None:
            queried_domains[tmp_domain]["method"] = int(tmp_application_identifier[2:4], 10)
        else:
            # Specify method to start with
            queried_domains[tmp_domain]["method"] = 0
            # For testing all methods randomly (lots of services only issue one DNS request)
            queried_domains[tmp_domain]["method"] = random.randint(0, len(methods) - 1)

    tmp_method = methods[queried_domains[tmp_domain]["method"] % len(methods)]


    ##### From here on the response packets are modified based on the incoming query #####


    ## React to special queries

    # let requests asking for defined nameserver entries through
    if analysis_domain in tmp_name and len(set(nameserver_prefixes).intersection(tmp_name.split("."))) > 0:
        return global_response

    # if the method number 99 is used in the defined format in an A request, this indicates that the response should not be changed (this can be used for debugging purposes)
    elif analysis_domain in tmp_name and re.match("^[0-9]{10}$", tmp_application_identifier) != None and int(tmp_application_identifier[2:4], 10) == 99:
        return global_response

    # IP FRAGMENTATION: if IP fragmentation works and a DNS name with the following format is queried, reply with an empty response
    elif (
        analysis_domain in tmp_name
        and re.search(
            "ns\.[a-z0-9]{10}\.if\.[0-9]{10}" + re.escape(dot_authoritative_domain_dot),
            tmp_name,
        )
        != None
    ):
        print("---> {}: Received a subsequent DNS query to an IP fragmented response".format(tmp_name))
        global_response = strip_dns_packet(global_response)

    # EDNS REMOVAL: if EDNS validation doesn't work and a DNS name with the following format is queried, don't reply anything
    elif (
        analysis_domain in tmp_name
        and re.search(
            "ns\.[a-z0-9]{10}\.er\.[0-9]{10}" + re.escape(dot_authoritative_domain_dot),
            tmp_name,
        )
        != None
    ):
        print("---> {}: Received a subsequent DNS query to a response without EDNS".format(tmp_name))
        global_response = strip_dns_packet(global_response)

    # EMPTY EDNS: if EDNS validation doesn't work and a DNS name with the following format is queried, don't reply anything
    elif (
        analysis_domain in tmp_name
        and re.search(
            "ns\.[a-z0-9]{10}\.ee\.[0-9]{10}" + re.escape(dot_authoritative_domain_dot),
            tmp_name,
        )
        != None
    ):
        print("---> {}: Received a subsequent DNS query to a response with an empty EDNS entry".format(tmp_name))
        global_response = strip_dns_packet(global_response)

    # RECUSRIVE DELEGATION: Recursively delegate queries that were recursively delegated
    elif (
        analysis_domain in tmp_name
        and re.search(
            "ns\.[a-z0-9]{10}\.rd\.[0-9]{10}" + re.escape(dot_authoritative_domain_dot),
            tmp_name,
        )
        != None
    ):

        global_response = strip_dns_packet(global_response)
        number_of_records_to_add = number_of_records_to_add_rd
        ns_nameserver_records = None

        # Create new NS records for authoritative NS section
        for new_records in range(0, number_of_records_to_add):
            ns_record = DNSRR()
            ns_record.type = 2
            ns_record.ttl = ttl_short
            ns_record.rrname = tmp_domain + dot_authoritative_domain_dot
            ns_record.rdata = "ns." + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".rd." + tmp_application_identifier + dot_authoritative_domain

            if ns_nameserver_records == None:
                ns_nameserver_records = ns_record
            else:
                ns_nameserver_records = ns_nameserver_records / ns_record

        global_response[DNS].ns = ns_nameserver_records
        global_response[DNS].nscount += number_of_records_to_add


    ## Craft special responses here
    # EXAMPLE response manipulation
    elif tmp_method == "0-tid" and analysis_domain in tmp_name:
        if global_response[DNS].id == 0:
            global_response[DNS].id = 1
        else:
            global_response[DNS].id = 0

        queried_domains[tmp_domain]["method"] += 1

    elif tmp_method == "random-tid" and analysis_domain in tmp_name:
        while True:
            tmp_int = randint(0, 65535)
            if tmp_int != global_response[DNS].id:
                break

        global_response[DNS].id = tmp_int

        queried_domains[tmp_domain]["method"] += 1

    elif tmp_method == "one-off-tid" and analysis_domain in tmp_name:
        if global_response[DNS].id > 30000:
            global_response[DNS].id -= 1
        else:
            global_response[DNS].id += 1

        queried_domains[tmp_domain]["method"] += 1

    elif tmp_method == "0-port" and analysis_domain in tmp_name:
        if global_response[tmp_layer_4_protocol].dport == 0:
            global_response[tmp_layer_4_protocol].dport = 1
        else:
            global_response[tmp_layer_4_protocol].dport = 0

        queried_domains[tmp_domain]["method"] += 1

    elif tmp_method == "random-port" and analysis_domain in tmp_name:
        while True:
            tmp_int = randint(0, 65535)
            if tmp_int != global_response[tmp_layer_4_protocol].dport:
                break

        global_response[tmp_layer_4_protocol].dport = tmp_int

        queried_domains[tmp_domain]["method"] += 1

    elif tmp_method == "one-off-port" and analysis_domain in tmp_name:
        if global_response[tmp_layer_4_protocol].dport > 30000:
            global_response[tmp_layer_4_protocol].dport -= 1
        else:
            global_response[tmp_layer_4_protocol].dport += 1

        queried_domains[tmp_domain]["method"] += 1

    # IP FRAGMENTATION TEST
    elif tmp_method == "ip_fragmentation" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        global_response = strip_dns_packet(global_response)

        number_of_records_to_add = 25
        ns_nameserver_records = None

        # Create new NS records for authoritative NS section
        for new_records in range(0, number_of_records_to_add):
            ns_record = DNSRR()
            ns_record.type = 2
            ns_record.ttl = ttl_short
            ns_record.rrname = tmp_domain + dot_authoritative_domain_dot
            ns_record.rdata = "ns." + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".if." + tmp_application_identifier + dot_authoritative_domain

            if ns_nameserver_records == None:
                ns_nameserver_records = ns_record
            else:
                ns_nameserver_records = ns_nameserver_records / ns_record

        global_response[DNS].ns = ns_nameserver_records
        global_response[DNS].nscount += number_of_records_to_add

        queried_domains[tmp_domain]["method"] += 1

    # EDNS REMOVAL
    elif tmp_method == "edns_removal" and analysis_domain in tmp_name and tmp_application_identifier != "0":
        # strip the whole packet
        global_response = strip_dns_packet(global_response)
        global_response[DNS].ar = None
        global_response[DNS].arcount = 0
        
        ns_record = DNSRR()
        ns_record.type = 2
        ns_record.ttl = ttl_short
        ns_record.rrname = tmp_domain + dot_authoritative_domain_dot
        ns_record.rdata = "ns." + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".er." + tmp_application_identifier + dot_authoritative_domain

        global_response[DNS].ns = ns_record
        global_response[DNS].nscount = 1

        queried_domains[tmp_domain]["method"] += 1

    # Empty EDNS
    elif tmp_method == "empty_edns" and analysis_domain in tmp_name and tmp_application_identifier != "0":
        # strip the whole packet
        global_response = strip_dns_packet(global_response)
        global_response[DNS].ar = DNSRROPT(rclass=4096)
        global_response[DNS].arcount = 1
        
        ns_record = DNSRR()
        ns_record.type = 2
        ns_record.ttl = ttl_short
        ns_record.rrname = tmp_domain + dot_authoritative_domain_dot
        ns_record.rdata = "ns." + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".ee." + tmp_application_identifier + dot_authoritative_domain

        global_response[DNS].ns = ns_record
        global_response[DNS].nscount = 1

        queried_domains[tmp_domain]["method"] += 1

    # RECUSRIVE DELEGATION: Recursively delegate to itself to generate DNS queries
    elif tmp_method == "recursive_delegation" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        global_response = strip_dns_packet(global_response)

        number_of_records_to_add = number_of_records_to_add_rd
        ns_nameserver_records = None

        # Create new NS records for authoritative NS section
        for new_records in range(0, number_of_records_to_add):
            ns_record = DNSRR()
            ns_record.type = 2
            ns_record.ttl = ttl_short
            ns_record.rrname = tmp_domain + dot_authoritative_domain_dot
            ns_record.rdata = "ns." + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".rd." + tmp_application_identifier + dot_authoritative_domain

            if ns_nameserver_records == None:
                ns_nameserver_records = ns_record
            else:
                ns_nameserver_records = ns_nameserver_records / ns_record

        global_response[DNS].ns = ns_nameserver_records
        global_response[DNS].nscount += number_of_records_to_add

        queried_domains[tmp_domain]["method"] += 1
        
    # ADDITIONAL QUESTION 1
    elif tmp_method == "additional_question_1" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        qd_record = DNSQR(qname="google.com")

        global_response[DNS].qd = global_response[DNS].qd / qd_record
        global_response[DNS].qdcount += 1

        queried_domains[tmp_domain]["method"] += 1
        
    # ADDITIONAL QUESTION 2
    elif tmp_method == "additional_question_2" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        qd_record = DNSQR(qname="google.com")

        global_response[DNS].qd = qd_record / global_response[DNS].qd
        global_response[DNS].qdcount += 1

        queried_domains[tmp_domain]["method"] += 1

    # ADDITIONAL QUESTION 3
    elif tmp_method == "additional_question_3" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        qd_record = DNSQR(qname="google.com")

        global_response[DNS].qd = global_response[DNS].qd / qd_record / global_response[DNS].qd
        global_response[DNS].qdcount += 2

        queried_domains[tmp_domain]["method"] += 1
        
    # ADDITIONAL QUESTION 4
    elif tmp_method == "additional_question_4" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        global_response[DNS].qd = global_response[DNS].qd / global_response[DNS].qd
        global_response[DNS].qdcount += 1

        queried_domains[tmp_domain]["method"] += 1

    # ADDITIONAL QUESTION 5
    elif tmp_method == "additional_question_5" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        qd_record = DNSQR(qname=tmp_name,qtype=16)

        global_response[DNS].qd = global_response[DNS].qd / qd_record
        global_response[DNS].qdcount += 1

        queried_domains[tmp_domain]["method"] += 1
        
    # ADDITIONAL QUESTION 6
    elif tmp_method == "additional_question_6" and analysis_domain in tmp_name and tmp_application_identifier != "0":

        qd_record = DNSQR(qname=tmp_name,qtype=16)

        global_response[DNS].qd = qd_record / global_response[DNS].qd
        global_response[DNS].qdcount += 1

        queried_domains[tmp_domain]["method"] += 1
        
    else:

        global_response = strip_dns_packet(global_response)

    return global_response


def traffic_check(pkt):

    # check layer 4 protocol
    layer_4_protocol = get_packet_protocol(pkt)

    # check if it's UDP and DNS traffic
    if layer_4_protocol != UDP or pkt.haslayer(DNS) == 0:
        print("Only UDP DNS traffic allowed!")
        return False

    print("SRC/DST IP: " + pkt[IP].src + "/" + pkt[IP].dst)
    if pkt[IP].dst != analysis_domain_ip:
        print("The destination IP is not the host IP! Skipping! (Scapy seems to sniff wrong packets)")
        return False

    # check if the request is coming from the host itself
    if pkt[IP].src == analysis_domain_ip:
        print("Locally sniffed DNS resolutions are ignored!")
        return False

    # check if the incoming DNS traffic can be decoded
    try:
        qtype = pkt[DNS].qd.qtype
        # lower because of 0x20 encoding
        qname = pkt[DNS].qd.qname.decode(encoding).lower()
        qdomain = qname.split(dot_authoritative_domain)[0]
    except:
        print("Error while decoding! #534523")
        return False

    # check if the it's a query for the analysis domain
    if analysis_domain not in qname:
        return False

    return True


def dns_proxy(pkt):

    # Checking traffic for legitimacy
    if not traffic_check(pkt):
        return

    # Extracting some initial information
    layer_4_protocol = get_packet_protocol(pkt)
    qname = pkt[DNS].qd.qname.decode(encoding).lower()
    qdomain = qname.split(dot_authoritative_domain)[0]

    if logging:
        # init log dict
        log_entry = {}

        if qdomain in queried_domains.keys():
            initial_method_counter = queried_domains[qdomain]["method"]
        else:
            initial_method_counter = 0

        # log packet data to dict
        log_entry["global_request"] = get_packet_data(pkt)
        # dump packet to pcap
        wrpcap("dns_dump.pcap", pkt, append=True)

    local_request = IP(dst="127.0.0.1") / pkt[layer_4_protocol]
    local_request[layer_4_protocol].sport = randint(50000, 60000)
    local_request[layer_4_protocol].dport = 54
    local_request[layer_4_protocol].chksum = None
    if layer_4_protocol == UDP:
        local_request[layer_4_protocol].len = None

    # Log request to bind9
    if logging and logging_mode == "FULL":
        log_entry["local_request"] = get_packet_data(local_request)

        # Adding MAC layer for pcap-dump logging
        tmp_local_request = Ether(src="53:53:53:53:53:53", dst="54:54:54:54:54:54") / local_request
        # To be able to inspect the DNS messages in Wireshark, the destination port needs to be set to 53
        tmp_local_request[layer_4_protocol].dport = 53
        wrpcap("dns_dump.pcap", tmp_local_request, append=True)

    # Relay DNS request to the local Bind9 service and read the response
    local_response = sr1(local_request)

    # The local response needs to be cast to DNS first (it's sent on port 54 and therefore doesn't get detected as DNS)
    local_response_payload = local_response.load
    local_response[layer_4_protocol].remove_payload()
    local_response = local_response / DNS(local_response_payload)

    # Log response from bind9
    if logging and logging_mode == "FULL":
        log_entry["local_response"] = get_packet_data(local_response)

        tmp_local_response = Ether(src="54:54:54:54:54:54", dst="53:53:53:53:53:53") / local_response
        # To be able to inspect the DNS messages in Wireshark, the source port needs to be set to 53
        tmp_local_response[layer_4_protocol].sport = 53
        wrpcap(dns_dump_file, tmp_local_response, append=True)

    # craft unmodified global response
    global_response = IP(dst=pkt[IP].src, src=pkt[IP].dst) / local_response[layer_4_protocol]
    global_response[layer_4_protocol].dport = pkt[layer_4_protocol].sport
    global_response[layer_4_protocol].sport = pkt[layer_4_protocol].dport
    global_response[layer_4_protocol].chksum = None
    if layer_4_protocol == UDP:
        global_response[layer_4_protocol].len = None

    # Crafting the response packet
    global_response = craft_analysis_packet(pkt, global_response)
    print("---> {}: Testing {}".format(qname, methods[(queried_domains[qdomain]["method"] - 1) % len(methods)]))

    # Log global response sent back to the resolver
    if logging:
        # Logging method and packet data
        if qdomain in queried_domains.keys() and queried_domains[qdomain]["method"] != initial_method_counter:
            log_entry["method"] = methods[(queried_domains[qdomain]["method"] - 1) % len(methods)]
            
        if logging_mode == "FULL":    
            log_entry["global_response"] = get_packet_data(global_response)

        # Adding MAC layer for logging
        tmp_global_response = Ether() / global_response
        wrpcap(dns_dump_file, tmp_global_response, append=True)

    # Append log to file
    if logging:
        dns_log = open(dns_log_file, "a")
        dns_log.write(json.dumps(log_entry))
        dns_log.write("\n")
        dns_log.close()

    global_response.show()
    # send back the modified response
    send(global_response)


if __name__ == '__main__':
    sniff(filter=BPF_FILTER, prn=dns_proxy, store=0)
