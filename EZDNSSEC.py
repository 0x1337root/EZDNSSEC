#!/bin/python3

#TO-DO {"DNSSEC", "SPF Node Check", "SPF MTA-STS TLS-RPT Flag Check", "STARTTLS Check", "Mail Spoofing Check", "SMTP Relay Check"}

import argparse, os, subprocess, re
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

def dmarc_control():
    if re.search("v=dmarc", dmarc_value.lower()):
        print(Fore.YELLOW + '\n[+] Your DMARC record "v" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '\n[!] You must specify a valid DMARC record "v" tag!' + Style.RESET_ALL)
    
    if re.search("p=none", dmarc_value.lower()):
        print(Fore.RED + '[!] Your DMARC record "p" tag is set to "none". You should change it!' + Style.RESET_ALL)
    elif re.search("p=reject", dmarc_value.lower()):
        print(Fore.YELLOW + '[+] Your DMARC record "p" tag is clearly configured' + Style.RESET_ALL)
    elif re.search("p=quarantine", dmarc_value.lower()):
        print(Fore.YELLOW + '[+] Your DMARC record "p" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "p" tag in your DMARC record. You must specify a valid "p" tag!' + Style.RESET_ALL)

    if re.search("rua=", dmarc_value.lower()):
        print(Fore.YELLOW + '[+] Your DMARC record "rua" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "rua" tag in your DMARC record. You must specify a valid "rua" tag!' + Style.RESET_ALL)

def dkim_control():
    if re.search("v=dkim", dkim_value.lower()):
        print(Fore.YELLOW + '\n[+] Your DKIM record "v" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '\n[!] You must specify a valid DKIM record "v" tag!' + Style.RESET_ALL)
    
    if re.search("k=", dkim_value.lower()):
        print(Fore.YELLOW + '[+] Your DKIM record "k" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "k" tag in your DKIM record. You must specify a valid "k" tag!' + Style.RESET_ALL)

    if re.search("p=", dkim_value.lower()):
        print(Fore.YELLOW + '[+] Your DKIM record "p" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "p" tag in your DKIM record. You must specify a valid "p" tag!' + Style.RESET_ALL)

def run_commands():
    print(Fore.MAGENTA + "\n-----------------------------------------" + Style.RESET_ALL)
    print(Fore.BLUE + "[+] MX Records" + Style.RESET_ALL)
    if mx_value == "b''":
        print(Fore.RED + "[-] There is no MX record found!" + Style.RESET_ALL)
    else:
        os.system(mx_command)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] MTA-STS Record" + Style.RESET_ALL)
    if mta_value == "b''":
        print(Fore.RED + "[-] There is no MTA-STS record found!" + Style.RESET_ALL)
    else:
        os.system(mta_command)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] TLS-RPT Record" + Style.RESET_ALL)
    if tls_value == "b''":
        print(Fore.RED + "[-] There is no TLS-RPT record found!" + Style.RESET_ALL)
    else:
        os.system(tls_command)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] SPF Record" + Style.RESET_ALL)
    if spf_value == "b''":
        print(Fore.RED + "[-] There is no SPF record found!" + Style.RESET_ALL)
    else:
        os.system(spf_command)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    #if spf_value.find('-all') != -1:
    #    print(Fore.MAGENTA + "[+] Your SPF record well-configured" + Style.RESET_ALL)
    #elif spf_value.find('~all') != -1:
    #    print(Fore.LIGHTYELLOW_EX + "[*] Your SPF record has a softfail" + Style.RESET_ALL)
    #else:
    #    print(Fore.RED + "[!] You must create SPF record" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] DMARC Record" + Style.RESET_ALL)
    if dmarc_value == "b''":
        print(Fore.RED + "[-] There is no DMARC record found!" + Style.RESET_ALL)
    else:
        os.system(dmarc_command)
        dmarc_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    if args.selector:
        print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
        if dkim_value == "b''":
            print(Fore.RED + "[-] There is no DKIM record found!" + Style.RESET_ALL)
        else:
            os.system(dkim_command)
            dkim_control()
    else:
        print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
        print(Fore.RED + "[-] There is no selector for DKIM record!, You can specify a selector with -s" + Style.RESET_ALL)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

run_commands()
