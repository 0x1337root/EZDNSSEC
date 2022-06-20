# EZDNSSEC
**EZDNSSEC** is a mail security tool. 
* Checking MX servers and list them by priority
* Checking STARTTLS
* Checking SMTP Open Relay for all MX servers
* Checking MTA-STS record
* Checking TLS-RPT record
* Checking SPF record
* Checking DMARC record
* Checking DKIM record
* Checking DNSSEC 
# Installation
1. Clone the repository to your machine : `git clone https://github.com/0x1337root/EZDNSSEC.git`
2. Go to the folder : `cd EZDNSSEC`
3. Make the tool executable : `chmod +x EZDNSSEC.py`
4. Install required modules : `pip3 install -r requirements.txt`
# Note
* Install figlet font "epic" if it does not exists on your system :<br> `wget http://www.figlet.org/fonts/epic.flf -O /usr/share/figlet/epic.flf`
# Usage
To get a list of all options and learn how to use this app, enter the following command :<br>
`./EZDNSSEC.py -h`<br><br>
**General Usage :** `./EZDNSSEC.py -d <domain> -s <selector>`<br><br>
**Example 1 :** `./EZDNSSEC.py -d example.com -or -st -ds`<br>
**Example 2 :** `./EZDNSSEC.py example.com -s selector -o <filename.json>`<br>
# Screenshot
![alt text](https://github.com/0x1337root/EZDNSSEC/blob/main/usage.PNG)
