#!/bin/python3

# Import necessary modules
import argparse, subprocess, re, smtplib, json
from colorama import init, Fore, Style
from pyfiglet import Figlet
from lxml import etree
from control_funcs import mail_srvr_list, smtp_open_relay_control, starttls_control, mta_control, tls_control, spf_control, dmarc_control, dkim_control

# Initialize colorama for colored console output
init()

# Create an argument parser
parser = argparse.ArgumentParser(description="Write the domain")
# Define command-line arguments
parser.add_argument('-d', '--domain', dest="domain", type=str, help="Domain to control")
parser.add_argument('-s', '--selector', dest="selector", type=str, help="DKIM selector")
parser.add_argument('-c', '--convert', dest="convert", type=str, help='Convert XML to HTML')
parser.add_argument('-or', '--open-relay', dest='open_relay', default=False, action='store_true', help='Check SMTP Open Relay')
parser.add_argument('-st', '--start-tls', dest='start_tls', default=False, action='store_true', help='Check STARTTLS')
parser.add_argument('-ds', '--dnssec', dest='dns_sec', default=False, action='store_true', help='Check DNSSEC')
parser.add_argument('-o', '--output', dest='output', type=str, help='Output to a JSON file')
# assigns parsed command line argumants to args
args = parser.parse_args()

# Print ASCII art using colorama and pyfiglet
#try:
    #custom_fig = Figlet(font='epic')
    #print()
    #print(Fore.RED + Style.BRIGHT + custom_fig.renderText('EZDNSSEC') + Style.RESET_ALL)
#except:
    # Incase of the errors while printing ASCII art 
    #print(f"Error occurred while printing ASCII art: {ascii_error}")

# Initialize a JSON string with an opening square bracket
json_data = '['

# Check if the 'domain' argument is provided
if args.domain:
        # Use dig command to fetch MX records for the given domain
        mx_value = str(subprocess.getoutput("dig +short MX " + args.domain + " | sort --numeric-sort"))
        # Extract individual MX servers from the dig output
        mx_list = re.findall(r"\S+\w+\.\w\w\w\b", mx_value)
        # Use dig command to fetch A, SOA, NS records for the given domain
        a_value =  str(subprocess.getoutput("dig +short A " + args.domain))
        ns_value = str(subprocess.getoutput("dig +short NS " + args.domain))
        soa_value = str(subprocess.getoutput("dig +short SOA " + args.domain))
        # Fetch MTA-STS, TLS-RPT, SPF, DMARC, and DKIM records for the domain
        mta_value = str(subprocess.getoutput("dig +short TXT _mta-sts." + args.domain))
        tls_value = str(subprocess.getoutput("dig +short TXT _smtp._tls." + args.domain))
        spf_value = str(subprocess.getoutput("dig +short TXT " + args.domain + " | grep -i 'v=spf'"))
        dmarc_value = str(subprocess.getoutput("dig +short TXT _dmarc." + args.domain))
        dkim_value = str(subprocess.getoutput("dig +short TXT " + str(args.selector) + "._domainkey." + args.domain))


def convert():
        # Parse the XSLT stylesheet document
        xslt_doc = etree.parse("./stylesheet.xslt")
        # Create an XSLT transformer using the parsed stylesheet document
        xslt_transformer = etree.XSLT(xslt_doc)
    
        # Parse the source XML document specified in the command-line arguments
        source_doc = etree.parse(args.convert)
        # Apply the XSLT transformation to the source document
        output_doc = xslt_transformer(source_doc)
        
        # Print the transformed document as a string
        print(str(output_doc))
        # Write the transformed document to an HTML file named "report.html"
        output_doc.write("report.html", pretty_print=True)

def run_commands(mx_list,json_data):
        #global json_data
        
        # Print a separator line for better output readability
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        # Print A Records
        print(Fore.BLUE + "[+] A Records" + Style.RESET_ALL)
        print(a_value)
        
        # Print a separator line for better output readability
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        # Print NS Records
        print(Fore.BLUE + "[+] NS Records" + Style.RESET_ALL)
        print(ns_value)
        
        # Print a separator line for better output readability
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        # Print SOA Records
        print(Fore.BLUE + "[+] SOA Records" + Style.RESET_ALL)
        print(soa_value)
        
        # Print a separator line for better output readability
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
        
        # Check and print MX Records
        print(Fore.BLUE + "[+] MX Records" + Style.RESET_ALL)
        if (mx_value == "b''") or (mx_value == None) or (mx_value == ""):
            # No MX records found
            print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
            json_data += '{"control_name":"MX_CHECK","status":"fail","value":"None","details":"There is no MX record found!"},'
        else:
            # MX records found, check for STARTTLS if specified
            if args.start_tls:
                starttls_control(mx_list, json_data)
            else:
                mail_srvr_list(mx_list, json_data)
                
                
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        # Check SMTP Open Relay Test if specified in command-line arguments
        if args.open_relay:
            print(Fore.BLUE + "[+] SMTP Open Relay Test" + Style.RESET_ALL)
            if (mx_value == "b''") or (mx_value == None) or (mx_value == ""):
                # No MX records found for SMTP Open Relay Test
                print(Fore.RED + "[!] There is no MX record found!" + Style.RESET_ALL)
                json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"There is no MX record found!"},'
            else:
                smtp_open_relay_control(mx_list,args, json_data)
            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        # Check and print MTA-STS Record
        print(Fore.BLUE + "[+] MTA-STS Record" + Style.RESET_ALL)
        if (mta_value == "b''") or (mta_value == "") or (mta_value == None):
            print(Fore.RED + "[!] There is no MTA-STS record found!" + Style.RESET_ALL)
            json_data += '{"control_name":"MTA_STS","status":"fail","value":"None","details":"There is no MTA-STS record found!"}'
        else:
            print(mta_value + "\n", end=None)
            mta_control(mta_value, json_data)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)


        # Check and print TLS-RPT Record
        print(Fore.BLUE + "[+] TLS-RPT Record" + Style.RESET_ALL)
        if (tls_value == "b''") or (tls_value == "") or (tls_value == None):
            print(Fore.RED + "[!] There is no TLS-RPT record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"TLS-RPT","status":"fail","value":"None","details":"There is no TLS-RPT record found!"}'
        else:
            print(tls_value + "\n", end=None)
            tls_control(tls_value, json_data)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        # Check and print SPF Record
        print(Fore.BLUE + "[+] SPF Record" + Style.RESET_ALL)
        if (spf_value == "b''") or (spf_value == "") or (spf_value == None):
            print(Fore.RED + "[!] There is no SPF record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"SPF_CHECK","status":"fail","value":"None","details":"There is no SPF record found!"}'
        else:
            print(spf_value, end=None)
            spf_control(spf_value, json_data)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        # Check and print DMARC Record
        print(Fore.BLUE + "[+] DMARC Record" + Style.RESET_ALL)
        if (dmarc_value == "b''") or (dmarc_value == "") or (dmarc_value == None):
            print(Fore.RED + "[!] There is no DMARC record found!" + Style.RESET_ALL)
            json_data += ',{"control_name":"DMARC_CHECK","status":"fail","value":"None","details":"There is no DMARC record found!"}'
        else:
            print(dmarc_value + "\n", end=None)
            dmarc_control(dmarc_value, json_data)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        # Check and print DKIM Record if selector is specified in command-line arguments
        if args.selector:
            print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
            if (dkim_value == "b''") or (dkim_value == "") or (dkim_value == None):
                print(Fore.RED + "[!] There is no DKIM record found!" + Style.RESET_ALL)
                json_data += ',{"control_name":"DKIM_CHECK","status":"fail","value":"None","details":"There is no DKIM record found!"}'
            else:
                print(dkim_value + "\n", end=None)
                dkim_control(dkim_value + "\n", json_data)
        else:
            print(Fore.BLUE + "[+] DKIM Record" + Style.RESET_ALL)
            print(Fore.RED + "\n[!] There is no selector for DKIM record!. You can specify a selector with -s" + Style.RESET_ALL)
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        # Check DNSSEC if specified in command-line arguments
        if args.dns_sec:
            print(Fore.BLUE + "[+] DNSSEC Check" + Style.RESET_ALL)
            try:
                # Execute a DNS query to fetch DS records for DNSSEC
                dnssec_value = str(subprocess.check_output("dig +short DS " + args.domain, shell=True))

                if (dnssec_value == "b''") or (dnssec_value == "") or (dnssec_value == None):
                    # DNSSEC is not enabled
                    print(Fore.RED + "\n[!] DNSSEC is not enabled!" + Style.RESET_ALL)
                    json_data += ',{"control_name":"DNSSEC_CHECK","status":"fail","details":"DNSSEC is not enabled!"}'
                else:
                    # DNSSEC is enabled, print and check
                    print(dnssec_value, end=None)
                    print(Fore.GREEN + '\n[+] Your DNSSEC is enabled' + Style.RESET_ALL)
                    json_data += ',{"control_name":"DNSSEC_CHECK","status":"pass","details":"Your DNSSEC is enabled"}'
            except:
                # Network Unreachable
                print(Fore.YELLOW + "[!] Network Unreachable!" + Style.RESET_ALL)
                json_data += ',{"control_name":"DNSSEC_CHECK","status":"fail","details":"Network Unreachable!"}'
            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
            
        # Closing the JSON data with the final square bracket    
        json_data += "]"

# Check if the domain argument is provided
if args.domain:
        # Execute the run_commands function to perform various DNS and email-related checks
        run_commands(mx_list, json_data)

        # Check if the output argument is provided
        if args.output:
            # Convert the JSON data string to a JSON object
            json_object = json.loads(json_data)
            
            # Pretty-print the JSON object with an indentation of 2 spaces
            json_formatted_str = json.dumps(json_object, indent=2)
            # Write the formatted JSON data to the specified output file
            with open(args.output, "w") as outfile:
                outfile.write(json_formatted_str)

# Check if the convert argument is provided
if args.convert:
        # Execute the convert function to transform XML to HTML
        convert()
