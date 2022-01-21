#!/bin/python3

import argparse, subprocess, re, smtplib
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

mx_value = str(subprocess.getoutput("dig +short MX " + args.domain + " | sort --numeric-sort"))
mx_list = re.findall(r"\S+\w+\.\w\w\w\b", mx_value)
starttls_list = []
mta_value = str(subprocess.getoutput("dig +short TXT _mta-sts." + args.domain))
tls_value = str(subprocess.getoutput("dig +short TXT _smtp._tls." + args.domain))
spf_value = str(subprocess.getoutput("dig +short TXT " + args.domain + " | grep -i 'v=spf'"))
dmarc_value = str(subprocess.getoutput("dig +short TXT _dmarc." + args.domain))
dkim_value = str(subprocess.getoutput("dig +short TXT " + str(args.selector) + "._domainkey." + args.domain))

def smtp_open_relay_control():
    sender = ["ezdnssec@yopmail.com", "ezdnssec@yopmail.com", "ezdnssec@" + args.domain]
    receiver = ["ezndssec@yopmail.com", "ezdnssec@" + args.domain, "ezdnssec@" + args.domain]

    for i in range(0, len(mx_list), 1):
        mx_server = mx_list[i]
        for i in range(0, 3, 1):
            message = """From: From Person <""" + sender[i] + """>
            To: To Person <""" + receiver[i] + """>
            Subject: SMTP open relay test

            This is a test e-mail message.
            """
            
            try:
                smtpObj = smtplib.SMTP(str(mx_server), 25)
                smtpObj.sendmail(sender[i], receiver[i], message)
                if i == 0:
                    print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from external source to external destination)" + Style.RESET_ALL)
                elif i == 1:
                    print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from external source to internal destination)" + Style.RESET_ALL)
                else:
                    print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from internal source to internal destination)" + Style.RESET_ALL)
            except:
                if i == 0:
                    print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to external destination)" + Style.RESET_ALL)
                elif i == 1:
                    print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to internal destination)" + Style.RESET_ALL)
                else:
                    print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from internal source to internal destination)" + Style.RESET_ALL)

def starttls_control():
    count = 0
    try:
        for i in mx_list:
            count += 1
            server = smtplib.SMTP(i, 25)
            starttls_list.append(str(server.starttls()))
        
        for i in range(count):
            if re.search("220", starttls_list[i]):
                print(mx_list[i] + Fore.GREEN + "          [+] STARTTLS supported" + Style.RESET_ALL)
            else:
                print(mx_list[i] + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
    except:
        for i in range(count):
            print(mx_list[i] + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
        
def mta_control():
    if re.search("v=sts", mta_value.lower()):
        print(Fore.GREEN + '\n[+] Your MTA-STS record "v" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] You must specify a valid MTA-STS record "v" tag!' + Style.RESET_ALL)

    if re.search("id=", mta_value.lower()):
        print(Fore.GREEN + '[+] Your MTA-STS record "id" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] You must specify a valid MTA-STS record "id" tag!' + Style.RESET_ALL)

def tls_control():
    if re.search("v=tlsrpt", tls_value.lower()):
        print(Fore.GREEN + '\n[+] Your TLS-RPT record "v" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] You must specify a valid TLS-RPT record "v" tag!' + Style.RESET_ALL)

    if re.search("rua=", tls_value.lower()):
        print(Fore.GREEN + '[+] Your TLS-RPT record "rua" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "rua" tag in your TLS-RPT record. You must specify a valid "rua" tag!' + Style.RESET_ALL)

def spf_control():
    if spf_value.find('-all') != -1:
        print(Fore.GREEN + "\n[+] Your SPF record well-configured" + Style.RESET_ALL)
    elif spf_value.find('~all') != -1:
        print(Fore.YELLOW + "\n[*] Your SPF record has a softfail, you should check sub nodes for SPF" + Style.RESET_ALL)
    else:
        print(Fore.RED + "\n[!] You must create SPF record or check sub nodes for SPF" + Style.RESET_ALL)

def dmarc_control():
    if re.search("p=none", dmarc_value.lower()):
        print(Fore.RED + '\n[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
        print(Fore.RED + '[!] Your DMARC record "p" tag is set to "none". Spoofed emails can be send to your inbox. You should change it!' + Style.RESET_ALL)
    elif re.search("p=reject", dmarc_value.lower()):
        print(Fore.GREEN + '\n[+] Your DMARC record "p" tag is clearly configured' + Style.RESET_ALL)
    elif re.search("p=quarantine", dmarc_value.lower()):
        print(Fore.YELLOW + '\n[*] Your DMARC record "p" tag is set to "quarantine". Spoofed emails can be send to your spam box!' + Style.RESET_ALL)
    else:
        print(Fore.RED + '\n[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
        print(Fore.RED + '[!] There is no "p" tag in your DMARC record. Spoofed emails can be send to your inbox. You must specify a valid "p" tag!' + Style.RESET_ALL)

    if re.search("v=dmarc", dmarc_value.lower()):
        print(Fore.GREEN + '[+] Your DMARC record "v" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] You must specify a valid DMARC record "v" tag!' + Style.RESET_ALL)

    if re.search("rua=", dmarc_value.lower()):
        print(Fore.GREEN + '[+] Your DMARC record "rua" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "rua" tag in your DMARC record. You must specify a valid "rua" tag!' + Style.RESET_ALL)

def dkim_control():
    if re.search("v=dkim", dkim_value.lower()):
        print(Fore.GREEN + '\n[+] Your DKIM record "v" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] You must specify a valid DKIM record "v" tag!' + Style.RESET_ALL)
    
    if re.search("k=", dkim_value.lower()):
        print(Fore.GREEN + '[+] Your DKIM record "k" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "k" tag in your DKIM record. You must specify a valid "k" tag!' + Style.RESET_ALL)

    if re.search("p=", dkim_value.lower()):
        print(Fore.GREEN + '[+] Your DKIM record "p" tag is clearly configured' + Style.RESET_ALL)
    else:
        print(Fore.RED + '[!] There is no "p" tag in your DKIM record. You must specify a valid "p" tag!' + Style.RESET_ALL)

def run_commands():    
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
    print(Fore.BLUE + "[+] MX Records" + Style.RESET_ALL)
    if mx_value == "b''":
        print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
    else:
        starttls_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] SMTP Open Relay Test" + Style.RESET_ALL)
    smtp_open_relay_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] MTA-STS Record" + Style.RESET_ALL)
    if mta_value == "b''":
        print(Fore.RED + "[!] There is no MTA-STS record found!" + Style.RESET_ALL)
    else:
        print(mta_value, end=None)
        mta_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] TLS-RPT Record" + Style.RESET_ALL)
    if tls_value == "b''":
        print(Fore.RED + "[!] There is no TLS-RPT record found!" + Style.RESET_ALL)
    else:
        print(tls_value, end=None)
        tls_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] SPF Record" + Style.RESET_ALL)
    if spf_value == "b''":
        print(Fore.RED + "[!] There is no SPF record found!" + Style.RESET_ALL)
    else:
        print(spf_value, end=None)
        spf_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] DMARC Record" + Style.RESET_ALL)
    if dmarc_value == "b''":
        print(Fore.RED + "[!] There is no DMARC record found!" + Style.RESET_ALL)
    else:
        print(dmarc_value, end=None)
        dmarc_control()
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    if args.selector:
        print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
        if dkim_value == "b''":
            print(Fore.RED + "[!] There is no DKIM record found!" + Style.RESET_ALL)
        else:
            print(dkim_value, end=None)
            dkim_control()
    else:
        print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
        print(Fore.RED + "\n[!] There is no selector for DKIM record!. You can specify a selector with -s" + Style.RESET_ALL)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

    print(Fore.BLUE + "[+] DNSSEC Check" + Style.RESET_ALL)
    try:
        dnssec_value = str(subprocess.check_output("dig +short DS " + args.domain, shell=True))

        if dnssec_value == "b''":
            print(Fore.RED + "\n[!] DNSSEC is not enabled!" + Style.RESET_ALL)
        else:
            print(dnssec_value, end=None)
            print(Fore.GREEN + '\n[+] Your DNSSEC is enabled' + Style.RESET_ALL)
    except:
        print(Fore.YELLOW + "[!] Network Unreachable!" + Style.RESET_ALL)
    print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

run_commands()
