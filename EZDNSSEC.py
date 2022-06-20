#!/bin/python3

import argparse, subprocess, re, smtplib, json
from colorama import init, Fore, Style
from pyfiglet import Figlet
from lxml import etree

init()

parser = argparse.ArgumentParser(description="Write the domain")
parser.add_argument('-d', '--domain', dest="domain", type=str, help="Domain to control")
parser.add_argument('-s', '--selector', dest="selector", type=str, help="DKIM selector")
parser.add_argument('-c', '--convert', dest="convert", type=str, help='Convert XML to HTML')
parser.add_argument('-or', '--open-relay', dest='open_relay', default=False, action='store_true', help='Check SMTP Open Relay')
parser.add_argument('-st', '--start-tls', dest='start_tls', default=False, action='store_true', help='Check STARTTLS')
parser.add_argument('-ds', '--dnssec', dest='dns_sec', default=False, action='store_true', help='Check DNSSEC')
parser.add_argument('-o', '--output', dest='output', type=str, help='Output to a JSON file')
args = parser.parse_args()

try:
    custom_fig = Figlet(font='epic')
    print()
    print(Fore.RED + Style.BRIGHT + custom_fig.renderText('EZDNSSEC') + Style.RESET_ALL)

    json_data = '['

    if args.domain:
        mx_value = str(subprocess.getoutput("dig +short MX " + args.domain + " | sort --numeric-sort"))
        mx_list = re.findall(r"\S+\w+\.\w\w\w\b", mx_value)
        starttls_list = []
        mta_value = str(subprocess.getoutput("dig +short TXT _mta-sts." + args.domain))
        tls_value = str(subprocess.getoutput("dig +short TXT _smtp._tls." + args.domain))
        spf_value = str(subprocess.getoutput("dig +short TXT " + args.domain + " | grep -i 'v=spf'"))
        dmarc_value = str(subprocess.getoutput("dig +short TXT _dmarc." + args.domain))
        dkim_value = str(subprocess.getoutput("dig +short TXT " + str(args.selector) + "._domainkey." + args.domain))

    def smtp_open_relay_control():
        global json_data
        sender = ["ezdnssec@protonmail.com", "ezdnssec@protonmail.com", "ezdnssec@" + args.domain]
        receiver = ["ezndssec@protonmail.com", "ezdnssec@" + args.domain, "ezdnssec@" + args.domain]

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
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from external source to external destination)"},'
                    elif i == 1:
                        print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from external source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from external source to internal destination)"},'
                    else:
                        print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from internal source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from internal source to internal destination)"},'
                except:
                    if i == 0:
                        print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to external destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from external source to external destination)"},'
                    elif i == 1:
                        print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from external source to internal destination)"},'
                    else:
                        print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from internal source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from internal source to internal destination)"},'

    def mail_srvr_list():
        global json_data
        for i in mx_list:
            print(i)
            json_data += '{"control_name":"MX_CHECK","status":"pass","value":"'+str(i)+'"},'

    def starttls_control():
        global json_data
        count = 0
        try:
            for i in mx_list:
                count += 1
                server = smtplib.SMTP(i, 25)
                starttls_list.append(str(server.starttls()))

            for i in range(count):
                if re.search("220", starttls_list[i]):
                    print(mx_list[i] + Fore.GREEN + "          [+] STARTTLS supported" + Style.RESET_ALL)
                    json_data += '{"control_name":"MX_CHECK","status":"pass","value":"'+str(mx_list[i])+'","details":"STARTTLS supported"},'
                else:
                    print(mx_list[i] + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
                    json_data += '{"control_name":"MX_CHECK","status":"warning","value":"'+str(mx_list[i])+'","details":"STARTTLS does not supported"},'
        except:
            for i in mx_list:
                print(i + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
                json_data += '{"control_name":"MX_CHECK","status":"warning","value":"'+str(i)+'","details":"STARTTLS does not supported"},'

    def mta_control():
        global json_data
        if re.search("v=sts", mta_value.lower()):
            print(Fore.GREEN + '\n[+] Your MTA-STS record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"pass","value":'+str(mta_value)+',"specified_tag":"v","details":"Your MTA-STS record v tag is clearly configured"},'
        else:
            print(Fore.RED + '[!] You must specify a valid MTA-STS record "v" tag!' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":'+str(mta_value)+',"specified_tag":"v","details":"You must specify a valid MTA-STS record v tag!"},'

        if re.search("id=", mta_value.lower()):
            print(Fore.GREEN + '[+] Your MTA-STS record "id" tag is clearly configured' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"pass","value":'+str(mta_value)+',"specified_tag":"id","details":"Your MTA-STS record id tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid MTA-STS record "id" tag!' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":'+str(mta_value)+',"specified_tag":"id","details":"You must specify a valid MTA-STS record id tag!"}'

    def tls_control():
        global json_data
        if re.search("v=tlsrpt", tls_value.lower()):
            print(Fore.GREEN + '\n[+] Your TLS-RPT record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"pass","value":'+str(tls_value)+',"specified_tag":"v","details":"Your TLS-RPT record v tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid TLS-RPT record "v" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"fail","value":'+str(tls_value)+',"specified_tag":"v","details":"You must specify a valid TLS-RPT record v tag!"}'

        if re.search("rua=", tls_value.lower()):
            print(Fore.GREEN + '[+] Your TLS-RPT record "rua" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"pass","value":'+str(tls_value)+',"specified_tag":"rua","details":"Your TLS-RPT record rua tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "rua" tag in your TLS-RPT record. You must specify a valid "rua" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"fail","value":'+str(tls_value)+',"specified_tag":"rua","details":"There is no rua tag in your TLS-RPT record. You must specify a valid rua tag!"}'

    def spf_control():
        global json_data
        if spf_value.find('-all') != -1:
            print(Fore.GREEN + "\n[+] Your SPF record well-configured" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"pass","value":'+str(spf_value)+',"details":"Your SPF record well-configured"}'
        elif spf_value.find('~all') != -1:
            print(Fore.YELLOW + "\n[*] Your SPF record has a softfail, you should check sub nodes for SPF" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"warning","value":'+str(spf_value)+',"details":"Your SPF record has a softfail, you should check sub nodes for SPF"}'
        else:
            print(Fore.RED + "\n[!] You must create SPF record or check sub nodes for SPF" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"fail","value":'+str(spf_value)+',"details":"You must create SPF record or check sub nodes for SPF"}'

    def dmarc_control():
        global json_data
        if re.search("p=none", dmarc_value.lower()):
            print(Fore.RED + '\n[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
            print(Fore.RED + '[!] Your DMARC record "p" tag is set to "none". Spoofed emails can be send to your inbox. You should change it!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your email is vulnerable to email spoofing! Your DMARC record p tag is set to none. Spoofed emails can be send to your inbox. You should change it!"}'
        elif re.search("p=reject", dmarc_value.lower()):
            print(Fore.GREEN + '\n[+] Your DMARC record "p" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"pass","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your DMARC record p tag is clearly configured"}'
        elif re.search("p=quarantine", dmarc_value.lower()):
            print(Fore.YELLOW + '\n[*] Your DMARC record "p" tag is set to "quarantine". Spoofed emails can be send to your spam box!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"warning","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your DMARC record p tag is set to quarantine. Spoofed emails can be send to your spam box!"}'
        else:
            print(Fore.RED + '\n[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
            print(Fore.RED + '[!] There is no "p" tag in your DMARC record. Spoofed emails can be send to your inbox. You must specify a valid "p" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your email is vulnerable to email spoofing! There is no p tag in your DMARC record. Spoofed emails can be send to your inbox. You must specify a valid p tag!"}'

        if re.search("v=dmarc", dmarc_value.lower()):
            print(Fore.GREEN + '[+] Your DMARC record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"pass","value":'+str(dmarc_value)+',"specified_tag":"v","details":"Your DMARC record v tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid DMARC record "v" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"v","details":"You must specify a valid DMARC record v tag!"}'

        if re.search("rua=", dmarc_value.lower()):
            print(Fore.GREEN + '[+] Your DMARC record "rua" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"pass","value":'+str(dmarc_value)+',"specified_tag":"rua","details":"Your DMARC record rua tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "rua" tag in your DMARC record. You must specify a valid "rua" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"rua","details":"There is no rua tag in your DMARC record. You must specify a valid rua tag!"}'

    def dkim_control():
        global json_data
        if re.search("v=dkim", dkim_value.lower()):
            print(Fore.GREEN + '\n[+] Your DKIM record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"pass","value":'+str(dkim_value)+',"specified_tag":"v","details":"Your DKIM record v tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid DKIM record "v" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":'+str(dkim_value)+',"specified_tag":"v","details":"You must specify a valid DKIM record v tag!"}'
        
        if re.search("k=", dkim_value.lower()):
            print(Fore.GREEN + '[+] Your DKIM record "k" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"pass","value":'+str(dkim_value)+',"specified_tag":"k","details":"Your DKIM record k tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "k" tag in your DKIM record. You must specify a valid "k" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":'+str(dkim_value)+',"specified_tag":"k","details":"There is no k tag in your DKIM record. You must specify a valid k tag!"}'

        if re.search("p=", dkim_value.lower()):
            print(Fore.GREEN + '[+] Your DKIM record "p" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"pass","value":'+str(dkim_value)+',"specified_tag":"p","details":"Your DKIM record p tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "p" tag in your DKIM record. You must specify a valid "p" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":'+str(dkim_value)+',"specified_tag":"p","details":"There is no p tag in your DKIM record. You must specify a valid p tag!"}'

    def convert():
        xslt_doc = etree.parse("./stylesheet.xslt")
        xslt_transformer = etree.XSLT(xslt_doc)
    
        source_doc = etree.parse(args.convert)
        output_doc = xslt_transformer(source_doc)
    
        print(str(output_doc))
        output_doc.write("report.html", pretty_print=True)

    def run_commands():
        global json_data

        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        print(Fore.BLUE + "[+] MX Records" + Style.RESET_ALL)
        if (mx_value == "b''") or (mx_value == None) or (mx_value == ""):
            print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
            json_data += '{"control_name":"MX_CHECK","status":"fail","value":"None","details":"There is no MX record found!"},'
        else:
            if args.start_tls:
                starttls_control()
            else:
                mail_srvr_list()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        if args.open_relay:
            print(Fore.BLUE + "[+] SMTP Open Relay Test" + Style.RESET_ALL)
            if (mx_value == "b''") or (mx_value == None) or (mx_value == ""):
                print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
                json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"There is no MX record found!"},'
            else:
                smtp_open_relay_control()
            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] MTA-STS Record" + Style.RESET_ALL)
        if (mta_value == "b''") or (mta_value == "") or (mta_value == None):
            print(Fore.RED + "[!] There is no MTA-STS record found!" + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":"None","details":"There is no MTA-STS record found!"}'
        else:
            print(mta_value, end=None)
            mta_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] TLS-RPT Record" + Style.RESET_ALL)
        if (tls_value == "b''") or (tls_value == "") or (tls_value == None):
            print(Fore.RED + "[!] There is no TLS-RPT record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS-RPT","status":"fail","value":"None","details":"There is no TLS-RPT record found!"}'
        else:
            print(tls_value, end=None)
            tls_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] SPF Record" + Style.RESET_ALL)
        if (spf_value == "b''") or (spf_value == "") or (spf_value == None):
            print(Fore.RED + "[!] There is no SPF record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"fail","value":"None","details":"There is no SPF record found!"}'
        else:
            print(spf_value, end=None)
            spf_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] DMARC Record" + Style.RESET_ALL)
        if (dmarc_value == "b''") or (dmarc_value == "") or (dmarc_value == None):
            print(Fore.RED + "[!] There is no DMARC record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":"None","details":"There is no DMARC record found!"}'
        else:
            print(dmarc_value, end=None)
            dmarc_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        if args.selector:
            print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
            if (dkim_value == "b''") or (dkim_value == "") or (dkim_value == None):
                print(Fore.RED + "[!] There is no DKIM record found!" + Style.RESET_ALL)
                json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":"None","details":"There is no DKIM record found!"}'
            else:
                print(dkim_value, end=None)
                dkim_control()
        else:
            print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
            print(Fore.RED + "\n[!] There is no selector for DKIM record!. You can specify a selector with -s" + Style.RESET_ALL)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        if args.dns_sec:
            print(Fore.BLUE + "[+] DNSSEC Check" + Style.RESET_ALL)
            try:
                dnssec_value = str(subprocess.check_output("dig +short DS " + args.domain, shell=True))

                if (dnssec_value == "b''") or (dnssec_value == "") or (dnssec_value == None):
                    print(Fore.RED + "\n[!] DNSSEC is not enabled!" + Style.RESET_ALL)
                    json_data += ',{"control_name":"DNSSEC_CHECK","status":"fail","details":"DNSSEC is not enabled!"}'
                else:
                    print(dnssec_value, end=None)
                    print(Fore.GREEN + '\n[+] Your DNSSEC is enabled' + Style.RESET_ALL)
                    json_data += ',{"control_name":"DNSSEC_CHECK","status":"pass","details":"Your DNSSEC is enabled"}'
            except:
                print(Fore.YELLOW + "[!] Network Unreachable!" + Style.RESET_ALL)
                json_data += ',{"control_name":"DNSSEC_CHECK","status":"fail","details":"Network Unreachable!"}'
            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        json_data += "]"

    if args.domain:
        run_commands()
        json_object = json.loads(json_data)
        json_formatted_str = json.dumps(json_object, indent=2)

        if args.output:
            with open(args.output, "w") as outfile:
                outfile.write(json_formatted_str)

    if args.convert:
        convert()

except:
    json_data = '['

    if args.domain:
        mx_value = str(subprocess.getoutput("dig +short MX " + args.domain + " | sort --numeric-sort"))
        mx_list = re.findall(r"\S+\w+\.\w\w\w\b", mx_value)
        starttls_list = []
        mta_value = str(subprocess.getoutput("dig +short TXT _mta-sts." + args.domain))
        tls_value = str(subprocess.getoutput("dig +short TXT _smtp._tls." + args.domain))
        spf_value = str(subprocess.getoutput("dig +short TXT " + args.domain + " | grep -i 'v=spf'"))
        dmarc_value = str(subprocess.getoutput("dig +short TXT _dmarc." + args.domain))
        dkim_value = str(subprocess.getoutput("dig +short TXT " + str(args.selector) + "._domainkey." + args.domain))

    def smtp_open_relay_control():
        global json_data
        sender = ["ezdnssec@protonmail.com", "ezdnssec@protonmail.com", "ezdnssec@" + args.domain]
        receiver = ["ezndssec@protonmail.com", "ezdnssec@" + args.domain, "ezdnssec@" + args.domain]

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
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from external source to external destination)"},'
                    elif i == 1:
                        print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from external source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from external source to internal destination)"},'
                    else:
                        print(mx_server + Fore.RED + "      [!] This mail server is vulnerable to SMTP Open Relay! (from internal source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from internal source to internal destination)"},'
                except:
                    if i == 0:
                        print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to external destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from external source to external destination)"},'
                    elif i == 1:
                        print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from external source to internal destination)"},'
                    else:
                        print(mx_server + Fore.GREEN + "      [+] This mail server is not vulnerable to SMTP Open Relay! (from internal source to internal destination)" + Style.RESET_ALL)
                        json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from internal source to internal destination)"},'

    def mail_srvr_list():
        global json_data
        for i in mx_list:
            print(i)
            json_data += '{"control_name":"MX_CHECK","status":"pass","value":"'+str(i)+'"},'

    def starttls_control():
        global json_data
        count = 0
        try:
            for i in mx_list:
                count += 1
                server = smtplib.SMTP(i, 25)
                starttls_list.append(str(server.starttls()))

            for i in range(count):
                if re.search("220", starttls_list[i]):
                    print(mx_list[i] + Fore.GREEN + "          [+] STARTTLS supported" + Style.RESET_ALL)
                    json_data += '{"control_name":"MX_CHECK","status":"pass","value":"'+str(mx_list[i])+'","details":"STARTTLS supported"},'
                else:
                    print(mx_list[i] + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
                    json_data += '{"control_name":"MX_CHECK","status":"warning","value":"'+str(mx_list[i])+'","details":"STARTTLS does not supported"},'
        except:
            for i in mx_list:
                print(i + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
                json_data += '{"control_name":"MX_CHECK","status":"warning","value":"'+str(i)+'","details":"STARTTLS does not supported"},'

    def mta_control():
        global json_data
        if re.search("v=sts", mta_value.lower()):
            print(Fore.GREEN + '\n[+] Your MTA-STS record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"pass","value":'+str(mta_value)+',"specified_tag":"v","details":"Your MTA-STS record v tag is clearly configured"},'
        else:
            print(Fore.RED + '[!] You must specify a valid MTA-STS record "v" tag!' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":'+str(mta_value)+',"specified_tag":"v","details":"You must specify a valid MTA-STS record v tag!"},'

        if re.search("id=", mta_value.lower()):
            print(Fore.GREEN + '[+] Your MTA-STS record "id" tag is clearly configured' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"pass","value":'+str(mta_value)+',"specified_tag":"id","details":"Your MTA-STS record id tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid MTA-STS record "id" tag!' + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":'+str(mta_value)+',"specified_tag":"id","details":"You must specify a valid MTA-STS record id tag!"}'

    def tls_control():
        global json_data
        if re.search("v=tlsrpt", tls_value.lower()):
            print(Fore.GREEN + '\n[+] Your TLS-RPT record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"pass","value":'+str(tls_value)+',"specified_tag":"v","details":"Your TLS-RPT record v tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid TLS-RPT record "v" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"fail","value":'+str(tls_value)+',"specified_tag":"v","details":"You must specify a valid TLS-RPT record v tag!"}'

        if re.search("rua=", tls_value.lower()):
            print(Fore.GREEN + '[+] Your TLS-RPT record "rua" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"pass","value":'+str(tls_value)+',"specified_tag":"rua","details":"Your TLS-RPT record rua tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "rua" tag in your TLS-RPT record. You must specify a valid "rua" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS_RPT","status":"fail","value":'+str(tls_value)+',"specified_tag":"rua","details":"There is no rua tag in your TLS-RPT record. You must specify a valid rua tag!"}'

    def spf_control():
        global json_data
        if spf_value.find('-all') != -1:
            print(Fore.GREEN + "\n[+] Your SPF record well-configured" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"pass","value":'+str(spf_value)+',"details":"Your SPF record well-configured"}'
        elif spf_value.find('~all') != -1:
            print(Fore.YELLOW + "\n[*] Your SPF record has a softfail, you should check sub nodes for SPF" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"warning","value":'+str(spf_value)+',"details":"Your SPF record has a softfail, you should check sub nodes for SPF"}'
        else:
            print(Fore.RED + "\n[!] You must create SPF record or check sub nodes for SPF" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"fail","value":'+str(spf_value)+',"details":"You must create SPF record or check sub nodes for SPF"}'

    def dmarc_control():
        global json_data
        if re.search("p=none", dmarc_value.lower()):
            print(Fore.RED + '\n[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
            print(Fore.RED + '[!] Your DMARC record "p" tag is set to "none". Spoofed emails can be send to your inbox. You should change it!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your email is vulnerable to email spoofing! Your DMARC record p tag is set to none. Spoofed emails can be send to your inbox. You should change it!"}'
        elif re.search("p=reject", dmarc_value.lower()):
            print(Fore.GREEN + '\n[+] Your DMARC record "p" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"pass","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your DMARC record p tag is clearly configured"}'
        elif re.search("p=quarantine", dmarc_value.lower()):
            print(Fore.YELLOW + '\n[*] Your DMARC record "p" tag is set to "quarantine". Spoofed emails can be send to your spam box!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"warning","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your DMARC record p tag is set to quarantine. Spoofed emails can be send to your spam box!"}'
        else:
            print(Fore.RED + '\n[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
            print(Fore.RED + '[!] There is no "p" tag in your DMARC record. Spoofed emails can be send to your inbox. You must specify a valid "p" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"p","details":"Your email is vulnerable to email spoofing! There is no p tag in your DMARC record. Spoofed emails can be send to your inbox. You must specify a valid p tag!"}'

        if re.search("v=dmarc", dmarc_value.lower()):
            print(Fore.GREEN + '[+] Your DMARC record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"pass","value":'+str(dmarc_value)+',"specified_tag":"v","details":"Your DMARC record v tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid DMARC record "v" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"v","details":"You must specify a valid DMARC record v tag!"}'

        if re.search("rua=", dmarc_value.lower()):
            print(Fore.GREEN + '[+] Your DMARC record "rua" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"pass","value":'+str(dmarc_value)+',"specified_tag":"rua","details":"Your DMARC record rua tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "rua" tag in your DMARC record. You must specify a valid "rua" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":'+str(dmarc_value)+',"specified_tag":"rua","details":"There is no rua tag in your DMARC record. You must specify a valid rua tag!"}'

    def dkim_control():
        global json_data
        if re.search("v=dkim", dkim_value.lower()):
            print(Fore.GREEN + '\n[+] Your DKIM record "v" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"pass","value":'+str(dkim_value)+',"specified_tag":"v","details":"Your DKIM record v tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] You must specify a valid DKIM record "v" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":'+str(dkim_value)+',"specified_tag":"v","details":"You must specify a valid DKIM record v tag!"}'
        
        if re.search("k=", dkim_value.lower()):
            print(Fore.GREEN + '[+] Your DKIM record "k" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"pass","value":'+str(dkim_value)+',"specified_tag":"k","details":"Your DKIM record k tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "k" tag in your DKIM record. You must specify a valid "k" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":'+str(dkim_value)+',"specified_tag":"k","details":"There is no k tag in your DKIM record. You must specify a valid k tag!"}'

        if re.search("p=", dkim_value.lower()):
            print(Fore.GREEN + '[+] Your DKIM record "p" tag is clearly configured' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"pass","value":'+str(dkim_value)+',"specified_tag":"p","details":"Your DKIM record p tag is clearly configured"}'
        else:
            print(Fore.RED + '[!] There is no "p" tag in your DKIM record. You must specify a valid "p" tag!' + Style.RESET_ALL)
            json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":'+str(dkim_value)+',"specified_tag":"p","details":"There is no p tag in your DKIM record. You must specify a valid p tag!"}'

    def convert():
        xslt_doc = etree.parse("./stylesheet.xslt")
        xslt_transformer = etree.XSLT(xslt_doc)
    
        source_doc = etree.parse(args.convert)
        output_doc = xslt_transformer(source_doc)
    
        print(str(output_doc))
        output_doc.write("report.html", pretty_print=True)

    def run_commands():
        global json_data

        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        print(Fore.BLUE + "[+] MX Records" + Style.RESET_ALL)
        if (mx_value == "b''") or (mx_value == None) or (mx_value == ""):
            print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
            json_data += '{"control_name":"MX_CHECK","status":"fail","value":"None","details":"There is no MX record found!"},'
        else:
            if args.start_tls:
                starttls_control()
            else:
                mail_srvr_list()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        if args.open_relay:
            print(Fore.BLUE + "[+] SMTP Open Relay Test" + Style.RESET_ALL)
            if (mx_value == "b''") or (mx_value == None) or (mx_value == ""):
                print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
                json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"There is no MX record found!"},'
            else:
                smtp_open_relay_control()
            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] MTA-STS Record" + Style.RESET_ALL)
        if (mta_value == "b''") or (mta_value == "") or (mta_value == None):
            print(Fore.RED + "[!] There is no MTA-STS record found!" + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":"None","details":"There is no MTA-STS record found!"}'
        else:
            print(mta_value, end=None)
            mta_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] TLS-RPT Record" + Style.RESET_ALL)
        if (tls_value == "b''") or (tls_value == "") or (tls_value == None):
            print(Fore.RED + "[!] There is no TLS-RPT record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS-RPT","status":"fail","value":"None","details":"There is no TLS-RPT record found!"}'
        else:
            print(tls_value, end=None)
            tls_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] SPF Record" + Style.RESET_ALL)
        if (spf_value == "b''") or (spf_value == "") or (spf_value == None):
            print(Fore.RED + "[!] There is no SPF record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"fail","value":"None","details":"There is no SPF record found!"}'
        else:
            print(spf_value, end=None)
            spf_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        print(Fore.BLUE + "[+] DMARC Record" + Style.RESET_ALL)
        if (dmarc_value == "b''") or (dmarc_value == "") or (dmarc_value == None):
            print(Fore.RED + "[!] There is no DMARC record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":"None","details":"There is no DMARC record found!"}'
        else:
            print(dmarc_value, end=None)
            dmarc_control()
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        if args.selector:
            print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
            if (dkim_value == "b''") or (dkim_value == "") or (dkim_value == None):
                print(Fore.RED + "[!] There is no DKIM record found!" + Style.RESET_ALL)
                json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":"None","details":"There is no DKIM record found!"}'
            else:
                print(dkim_value, end=None)
                dkim_control()
        else:
            print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
            print(Fore.RED + "\n[!] There is no selector for DKIM record!. You can specify a selector with -s" + Style.RESET_ALL)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        if args.dns_sec:
            print(Fore.BLUE + "[+] DNSSEC Check" + Style.RESET_ALL)
            try:
                dnssec_value = str(subprocess.check_output("dig +short DS " + args.domain, shell=True))

                if (dnssec_value == "b''") or (dnssec_value == "") or (dnssec_value == None):
                    print(Fore.RED + "\n[!] DNSSEC is not enabled!" + Style.RESET_ALL)
                    json_data += ',{"control_name":"DNSSEC_CHECK","status":"fail","details":"DNSSEC is not enabled!"}'
                else:
                    print(dnssec_value, end=None)
                    print(Fore.GREEN + '\n[+] Your DNSSEC is enabled' + Style.RESET_ALL)
                    json_data += ',{"control_name":"DNSSEC_CHECK","status":"pass","details":"Your DNSSEC is enabled"}'
            except:
                print(Fore.YELLOW + "[!] Network Unreachable!" + Style.RESET_ALL)
                json_data += ',{"control_name":"DNSSEC_CHECK","status":"fail","details":"Network Unreachable!"}'
            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        json_data += "]"

    if args.domain:
        run_commands()
        json_object = json.loads(json_data)
        json_formatted_str = json.dumps(json_object, indent=2)

        if args.output:
            with open(args.output, "w") as outfile:
                outfile.write(json_formatted_str)

    if args.convert:
        convert()
