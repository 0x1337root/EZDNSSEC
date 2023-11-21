# Import necessary libraries
from colorama import Fore, Style
import concurrent.futures
import argparse, subprocess, re, smtplib, json
from colorama import init, Fore, Style
from pyfiglet import Figlet
from lxml import etree

# Function to control SMTP open relay
def smtp_open_relay_control(mx_list,args, json_data):
    
            # Define sender and receiver addresses for testing SMTP open relay
            sender = ["ezdnssec@protonmail.com", "ezdnssec@protonmail.com", "ezdnssec@" + args.domain]
            receiver = ["ezndssec@protonmail.com", "ezdnssec@" + args.domain, "ezdnssec@" + args.domain]

            # Define a function to test open relay on a specific mail server
            def test_relay(mx_server, sender, receiver):
                try:
                    # Attempt to establish a connection to the SMTP server
                    smtpObj = smtplib.SMTP(str(mx_server), 25)
                    
                    # Iterate over sender and receiver pairs for testing
                    for j in range(3):
                    
                        # Compose a test email message
                        message = f"""From: From Person <{sender[j]}>
                        To: To Person <{receiver[j]}>
                        Subject: SMTP open relay test
                        This is a test e-mail message.
                        """
                        # Send the test email
                        smtpObj.sendmail(sender[j], receiver[j], message)
                        # Check for vulnerability based on the test 
                        if j == 0:
                            print(mx_server + Fore.RED + f"      [!] This mail server is vulnerable to SMTP Open Relay! (from external source to external destination)" + Style.RESET_ALL)
                            json_data += '{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from external source to external destination)"},'
                        else:
                            print(mx_server + Fore.RED + f"      [!] This mail server is vulnerable to SMTP Open Relay! (from {'external' if j == 1 else 'internal'} source to {'internal' if j == 2 else 'external'} destination)" + Style.RESET_ALL)
                            json_data += f'{{"control_name":"OPEN_RELAY_CHECK","status":"fail","details":"This mail server is vulnerable to SMTP Open Relay! (from {"external" if j == 1 else "internal"} source to {"internal" if j == 2 else "external"} destination)"}},'

                except Exception as e:
                
                # Handle exceptions (mail server is not vulnerable)
                    for j in range(3):
                        if j == 0:
                            print(mx_server + Fore.GREEN + f"      [+] This mail server is not vulnerable to SMTP Open Relay! (from external source to {'external' if j == 1 else 'internal'} destination)" + Style.RESET_ALL)
                            json_data += f'{{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from external source to {"external" if j == 1 else "internal"} destination)"}},'
                        else:
                            print(mx_server + Fore.GREEN + f"      [+] This mail server is not vulnerable to SMTP Open Relay! (from {'external' if j == 1 else 'internal'} source to {'internal' if j == 2 else 'external'} destination)" + Style.RESET_ALL)
                            json_data += f'{{"control_name":"OPEN_RELAY_CHECK","status":"pass","details":"This mail server is not vulnerable to SMTP Open Relay! (from {"external" if j == 1 else "internal"} source to {"internal" if j == 2 else "external"} destination)"}},'

            # Use ThreadPoolExecutor for concurrent testing of multiple servers
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.map(test_relay, mx_list, [sender] * len(mx_list), [receiver] * len(mx_list))



# Function to check mail server list
def mail_srvr_list(mx_list, json_data):
        # Iterate over each mail server in the list
        for i in mx_list:
            # Print the current mail server
            print(i)
            
            # Update the JSON data with information about the current mail server
            json_data += '{"control_name":"MX_CHECK","status":"pass","value":"'+str(i)+'"},'



# Function to check STARTTLS support for mail servers
def starttls_control(mx_list, json_data):
        # Initialize counters
        count = 0
        # List to store STARTTLS results
        starttls_list = []
       
        try:
            # Check STARTTLS support for each MX server
            for mx_server in mx_list:
                count += 1
                # Connect to the mail server
                server = smtplib.SMTP(i, 25)
                
                # Attempt to start TLS
                starttls_list.append(str(server.starttls()))
            # Process the results
            for i in range(count):
                if re.search("220", starttls_list[i]):
                    # 220 response typically indicates successful STARTTLS negotiation.So STARTTLS is supported
                    print(mx_list[i] + Fore.GREEN + "          [+] STARTTLS supported" + Style.RESET_ALL)
                    json_data += '{"control_name":"MX_CHECK","status":"pass","value":"'+str(mx_list[i])+'","details":"STARTTLS supported"},'
                else:
                    # STARTTLS is not supported
                    print(mx_list[i] + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
                    json_data += '{"control_name":"MX_CHECK","status":"warning","value":"'+str(mx_list[i])+'","details":"STARTTLS does not supported"},'
        except:
            # Handle exceptions, print error, and update JSON data
            for mx_server in mx_list:
                print(mx_server + Fore.RED + "          [!] STARTTLS does not supported!" + Style.RESET_ALL)
                json_data += '{"control_name":"MX_CHECK","status":"warning","value":"'+str(mx_list)+'","details":"STARTTLS does not supported"},'
             
                
# Function to check MTA-STS record
def mta_control(mta_value, json_data):
        # Format the MTA value for consistent comparison
        formatted_mta_value = mta_value.lower().strip('"')

        # Define the tags to check
        tags_to_check = ["v", "id"]

        for tag in tags_to_check:
            if re.search(f"{tag}=", formatted_mta_value):
                # MTA-STS record tag is present and configured
                print(Fore.GREEN + f'[+] Your MTA-STS record "{tag}" tag is clearly configured' + Style.RESET_ALL)
                json_data += f'{{"control_name":"MTA_STS","status":"pass","value":"{formatted_mta_value}","specified_tag":"{tag}","details":"Your MTA-STS record {tag} tag is clearly configured"}},'
            else:
                # MTA-STS record tag is missing or not configured
                print(Fore.RED + f'[!] You must specify a valid MTA-STS record "{tag}" tag!' + Style.RESET_ALL)
                json_data += f'{{"control_name":"MTA_STS","status":"fail","value":"{formatted_mta_value}","specified_tag":"{tag}","details":"You must specify a valid MTA-STS record {tag} tag!"}},'
                
                
# Function to check TLS-RPT record                
def tls_control(tls_value, json_data):
            # Format the TLS value for consistent comparison
            formatted_tls_value = tls_value.lower().strip('"')

            # Define the tags to check
            tags_to_check = ["v", "rua"]

            for tag in tags_to_check:
                if re.search(f"{tag}=", formatted_tls_value):
                    print(Fore.GREEN + f'[+] Your TLS-RPT record "{tag}" tag is clearly configured' + Style.RESET_ALL)
                    json_data += f'{{"control_name":"TLS_RPT","status":"pass","value":"{formatted_tls_value}","specified_tag":"{tag}","details":"Your TLS-RPT record {tag} tag is clearly configured"}},'
                else:
                    print(Fore.RED + f'[!] You must specify a valid TLS-RPT record "{tag}" tag!' + Style.RESET_ALL)
                    json_data += f'{{"control_name":"TLS_RPT","status":"fail","value":"{formatted_tls_value}","specified_tag":"{tag}","details":"You must specify a valid TLS-RPT record {tag} tag!"}},'


# Function to check SPF record 
def spf_control(spf_value, json_data):
        # Format the SPF value for consistent comparison
        formatted_spf_value = spf_value.lower().strip('"')

        # Define the tags to check
        tags_to_check = ["-all", "~all"]

        for tag in tags_to_check:
            # TLS-RPT record tag is present and configured
            if tag in formatted_spf_value:
                status, message = ("pass", "well-configured") if tag == "-all" else ("warning", "has a softfail, you should check sub nodes for SPF")
                print(Fore.GREEN + f"\n[+] Your SPF record {message}" if tag == "-all" else Fore.YELLOW + f"\n[*] Your SPF record {message}")
                json_data += f'{{"control_name":"SPF_CHECK","status":"{status}","value":"{formatted_spf_value}","details":"Your SPF record {message}"}},'
                break
        else:
            # TLS-RPT record tag is missing or not configured
            print(Fore.RED + "\n[!] You must create SPF record or check sub nodes for SPF" + Style.RESET_ALL)
            json_data += f'{{"control_name":"SPF_CHECK","status":"fail","value":"{formatted_spf_value}","details":"You must create SPF record or check sub nodes for SPF"}},' 



# Function to check DMARC record 
def dmarc_control(dmarc_value, json_data):
    # Format the DMARC value for consistent comparison
    formatted_dmarc_value = dmarc_value.lower().strip('"')

    # Define the tags to check
    tags_to_check = ["p", "v", "rua"]

    # Loop through each tag to check in the DKIM record
    for tag in tags_to_check:
        # Search for the tag and its value in the DMARC record
        tag_value = re.search(f"{tag}=([^;]+)", formatted_dmarc_value)
        if tag_value:
            # Extract the value of the tag
            tag_value = tag_value.group(1)
            # Determine status and message for the tag
            status, message = ("pass", "well-configured") if tag == "p" and tag_value in ["reject"] else ("pass", "clearly configured")
            # Check for specific values of the "p" tag and print appropriate messages
            if tag == "p" and tag_value == "none":
                print(Fore.RED + '[!] Your email is vulnerable to email spoofing!' + Style.RESET_ALL)
                print(Fore.RED + '[!] Your DMARC record "p" tag is set to "none". Spoofed emails can be sent to your inbox. You should change it!' + Style.RESET_ALL)
            elif tag == "p" and tag_value == "quarantine":
                print(Fore.YELLOW + f'[*] Your DMARC record "{tag}" tag is set to "{tag_value}". Spoofed emails can be sent to your spam box!' + Style.RESET_ALL)
            else:
                print(Fore.GREEN + f'[+] Your DMARC record "{tag}" tag is {message}' + Style.RESET_ALL)

            json_data += f'{{"control_name":"DMARC_CHECK","status":"{status}","value":"{formatted_dmarc_value}","specified_tag":"{tag}","details":"Your DMARC record {tag} tag is {message}"}},'
        else:
            # Determine status and message for missing or invalid tag
            status, message = ("fail", "vulnerable to email spoofing") if tag == "p" else ("fail", f'You must specify a valid DMARC record {tag} tag!')
            print(Fore.RED + f'[!] Your email is {message}' if tag == "p" else f'[!] There is no "{tag}" tag in your DMARC record. {message}')
            # Update JSON data with the DMARC check result
            json_data += f'{{"control_name":"DMARC_CHECK","status":"{status}","value":"{formatted_dmarc_value}","specified_tag":"{tag}","details":"Your email is {message}"}},'

  
 
# Function to check DKIM record 
def dkim_control(dkim_value, json_data):
        # Format the DKIM value for consistent comparison
        formatted_dkim_value = dkim_value.lower().strip('"')

        # Define the tags to check
        tags_to_check = ["v", "k", "p"]

        # Loop through each tag to check in the DKIM record
        for tag in tags_to_check:
            # Search for the tag and its value in the DKIM record
            if re.search(f"{tag}=(\S+)", formatted_dkim_value):
                # Print success message for configured tag
                print(Fore.GREEN + f'[+] Your DKIM record "{tag}" tag is clearly configured' + Style.RESET_ALL)
                json_data += f'{{"control_name":"DKIM_CHECK","status":"pass","value":"{formatted_dkim_value}","specified_tag":"{tag}","details":"Your DKIM record {tag} tag is clearly configured"}},'
            else:
                # Print failure message for missing or invalid tag
                print(Fore.RED + f'[!] There is no "{tag}" tag in your DKIM record. You must specify a valid "{tag}" tag!' + Style.RESET_ALL)
                json_data += f'{{"control_name":"DKIM_CHECK","status":"fail","value":"{formatted_dkim_value}","specified_tag":"{tag}","details":"There is no {tag} tag in your DKIM record. You must specify a valid {tag} tag!"}},'
        
