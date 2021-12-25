#!/bin/python3

#TO-DO {"README", "DNSSEC", "SPF Node Check", "SPF DMARC DKIM MTA-STS TLS-RPT Flag Check", "Recommendations"}

import argparse, os, subprocess
from colorama import init, Fore, Style
from pyfiglet import Figlet

init()

parser = argparse.ArgumentParser(description="Write the domain")
parser.add_argument('domain', type=str, help="Domain to control")
parser.add_argument('-s', dest="selector", type=str, help="DKIM selector")
args = parser.parse_args()

custom_fig = Figlet(font='epic')
print()
print(Fore.RED + Style.BRIGHT + custom_fig.renderText('EZDNSSEC') + Style.RESET_ALL)

mx_command = "dig +short MX " + args.domain + " | sort --numeric-sort"
mx_value = str(subprocess.check_output("dig +short MX " + args.domain + " | sort --numeric-sort", shell=True))
mta_command = "dig +short TXT _mta-sts." + args.domain
mta_value = str(subprocess.check_output("dig +short TXT _mta-sts." + args.domain, shell=True))
tls_command = "dig +short TXT _smtp._tls." + args.domain
tls_value = str(subprocess.check_output("dig +short TXT _smtp._tls." + args.domain, shell=True))
spf_command = "dig +short TXT " + args.domain + " | grep -i 'v=spf'"
spf_value = str(subprocess.check_output("dig +short TXT " + args.domain + " | grep -i 'v=spf'", shell=True))
dmarc_command = "dig +short TXT _dmarc." + args.domain
dmarc_value = str(subprocess.check_output("dig +short TXT _dmarc." + args.domain, shell=True))
dkim_command = "dig +short TXT " + str(args.selector) + "._domainkey." + args.domain
dkim_value = str(subprocess.check_output("dig +short TXT " + str(args.selector) + "._domainkey." + args.domain, shell=True))

def run_commands():
    print(Fore.BLUE + "[+] MX Records" + Style.RESET_ALL)
    if mx_value == "b''":
        print(Fore.RED + "[-] There is no MX record found!" + Style.RESET_ALL)
    else:
        os.system(mx_command)
    
    print(Fore.BLUE + "\n[+] MTA-STS Record" + Style.RESET_ALL)
    if mta_value == "b''":
        print(Fore.RED + "[-] There is no MTA-STS record found!" + Style.RESET_ALL)
    else:
        os.system(mta_command)

    print(Fore.BLUE + "\n[+] TLS-RPT Record" + Style.RESET_ALL)
    if tls_value == "b''":
        print(Fore.RED + "[-] There is no TLS-RPT record found!" + Style.RESET_ALL)
    else:
        os.system(tls_command)

    print(Fore.BLUE + "\n[+] SPF Record" + Style.RESET_ALL)
    if spf_value == "b''":
        print(Fore.RED + "[-] There is no SPF record found!" + Style.RESET_ALL)
    else:
        os.system(spf_command)

    #if spf_value.find('-all') != -1:
    #    print(Fore.CYAN + "[+] Your SPF record well-configured" + Style.RESET_ALL)
    #elif spf_value.find('~all') != -1:
    #    print(Fore.LIGHTYELLOW_EX + "[*] Your SPF record has a softfail" + Style.RESET_ALL)
    #else:
    #    print(Fore.RED + "[!] You must create SPF record" + Style.RESET_ALL)

    print(Fore.BLUE + "\n[+] DMARC Record" + Style.RESET_ALL)
    if dmarc_value == "b''":
        print(Fore.RED + "[-] There is no DMARC record found!" + Style.RESET_ALL)
    else:
        os.system(dmarc_command)

    if args.selector:
        print(Fore.BLUE + "\n[+] DKIM Record" + Style.RESET_ALL)
        if dkim_value == "b''":
            print(Fore.RED + "[-] There is no DKIM record found!" + Style.RESET_ALL)
        else:
            os.system(dkim_command)
    else:
        print(Fore.BLUE + "\n[+] DKIM Record" + Style.RESET_ALL)
        print(Fore.RED + "[-] There is no selector for DKIM record!, You can specify a selector with -s" + Style.RESET_ALL)

run_commands()