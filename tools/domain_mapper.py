import argparse
import json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A script to create a mapping between analysis IDs (e.g., 0100001337) and domains (e.g., google.com).")
    parser.add_argument("--domain-file", type=str, required=True, help="Path to domain file (domains seperated by newlines).")
    parser.add_argument("--version-number", type=int, default=0, help="Version number to use.")
    parser.add_argument("--start-method", type=int, default=0, help="Integer (starting at 0) of the analysis method to start with.")
    parser.add_argument("--start-id", type=int, default=0, help="Integer (starting at 0) of the id to start at.")
    args = parser.parse_args()

    domains = []
    try:
        raw_domains = open(args.domain_file,"r").read()
        for domain in raw_domains.split("\n"):
            domains.append(domain.strip())
    except:
        print("Please provide a valid domain file!")
        quit()

    domain_mappings = {}
    mapping_file = open("../data/domain_mappings.json","w")

    for i,domain in enumerate(domains):
        domain_mappings[str(args.version_number).zfill(2) + str(args.start_method).zfill(2) + str(args.start_id + i).zfill(6)] = domain

    mapping_file.write(json.dumps(domain_mappings))