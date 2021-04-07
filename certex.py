import certstream
import argparse
import sys

BLUE='\033[94m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CLEAR='\x1b[0m'

print(BLUE + "Certex[1.2] by ARPSyndicate" + CLEAR)
print(YELLOW + "monitors certificate transparency logs" + CLEAR)

if len(sys.argv)<2:
	print(RED + "[!] ./certex --help" + CLEAR)
	sys.exit()
else:
    parser=argparse.ArgumentParser()
    parser.add_argument("-f", "--file", default=False, type=str, nargs='?', help="file containing domains to be monitored")
    parser.add_argument("-d", "--domains", default=[], type=str, nargs='+', help="domains to be monitored")
    parser.add_argument("-o", "--output", type=str, help="output file")    

args = parser.parse_args()
if not args.domains and not args.file:
    parser.error(RED + "[!] list of domains not given" + CLEAR)
domains =[]
if not args.file:
    domains = args.domains
else:
    with open(args.file, 'r') as f:
        domains = f.read().splitlines()
output = args.output

print(YELLOW + "[*] monitoring for: " + str(domains) + CLEAR)

def process(message, context):
    if message['message_type'] == "heartbeat":
        return
    if message['message_type'] == "certificate_update":
        cert_domains = message['data']['leaf_cert']['all_domains']
        if len(cert_domains) != 0:
           identify(cert_domains)
    return

def identify(cert_domains):
    found = []
    for doms in cert_domains:
        if any(doms.endswith("."+dom) for dom in domains):
            found.append(doms.replace("*.",""))
            
    found = list(set(found))
    for dom in found:
        print(BLUE + "[+] "+ dom + CLEAR)
    if args.output:
        with open(output, 'r') as f:
            found.extend(f.read().splitlines())
            found = list(set(found))
            found.sort()
            f.close()
        with open(output, 'w') as f:
            f.writelines("%s\n" % line for line in found)

certstream.listen_for_events(process, url='wss://certstream.calidog.io/')