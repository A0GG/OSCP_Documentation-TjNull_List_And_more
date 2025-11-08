## 🔍 Reconnaissance (Machines 41–50)

```bash
# Nmap Scans
nmap -p- --min-rate 10000 <IP>              # Fast full port scan  
nmap -p <ports> -sCV -oA scan <IP>          # Service/version detection  
nmap -T4 -A -v <IP>                          # Aggressive scan with OS detection and versioning  

# Service Enumeration
nmap --script=http-enum -p 80 <IP>          # HTTP service enumeration  
nmap --script=smb-os-discovery -p 445 <IP>  # SMB OS info  
nmap --script=ftp-anon -p 21 <IP>           # FTP anonymous login check  

# Web Tech Identification
whatweb http://<IP>                         # CMS/tech stack detection  
wappalyzer http://<IP>                      # Web tech fingerprinting  

# Directory Brute-Forcing
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt  

# DNS and Hostname Enumeration
dig <domain> any                            # DNS record check  
nslookup <domain>                           # Basic DNS lookup  
whois <domain>                              # WHOIS data

# Virtual Host / Subdomain Recon
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<IP>/ -H "Host: FUZZ.target.com"

# Banner Grabbing
nc -vn <IP> <port>                          # Grab service banner
```
