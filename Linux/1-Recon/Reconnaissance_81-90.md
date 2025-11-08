## 🔍 Reconnaissance (Machines 81–90)

```bash
# Common Port Scanning
nmap -p- --min-rate 10000 <IP>                    # Fast port scan
nmap -p <ports> -sCV -oA scan <IP>                # Service and version detection
nmap -T4 -A -v <IP>                                # Aggressive scan with OS and script scan

# Web Enumeration
whatweb http://<IP>                                # Identify web technologies
gobuster dir -u http://<IP> -w <wordlist> -x php,html,txt  # Directory brute-forcing

# DNS and Host Discovery
nslookup <domain>
dig <domain> any
whois <domain>
fierce --domain <domain>                          # Subdomain and DNS enumeration

# Banner Grabbing and Manual Checks
curl -I http://<IP>                                # Check HTTP headers
telnet <IP> <port>
nc -nv <IP> <port>                                 # Banner grabbing

# SMB Enumeration
nmap --script smb-enum-shares,smb-enum-users -p 139,445 <IP>
smbclient -L //<IP> -N                              # List SMB shares anonymously
enum4linux-ng <IP>                                 # Deep SMB/NetBIOS enum

# FTP Enumeration
nmap --script ftp-anon,ftp-bounce -p 21 <IP>
ftp <IP>                                           # Try anonymous login

# SNMP Enumeration
nmap -sU -p 161 --script=snmp* <IP>
snmpwalk -v2c -c public <IP>                       # Community string “public”
```
