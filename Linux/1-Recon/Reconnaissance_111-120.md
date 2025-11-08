## 🔍 Reconnaissance (Machines 111–120)

```bash
# General Port Scanning
nmap -p- --min-rate 10000 -T4 <IP>                  # Full TCP port scan
nmap -sC -sV -p <open-ports> -oN nmap_scan.txt <IP> # Default scripts, service/version detection

# Web Reconnaissance
whatweb http://<IP>                                # Web server & framework detection
gobuster dir -u http://<IP> -w common.txt -x php,txt,html -t 50

# DNS Enumeration
nslookup <domain>
dig <domain> any
whois <domain>

# Banner Grabbing & Service Fingerprinting
nc -vn <IP> <port>
telnet <IP> <port>
curl -I http://<IP>

# Subdomain Discovery
ffuf -u http://<IP> -H "Host: FUZZ.<domain>" -w subdomains.txt

# Virtual Host Detection
curl -H "Host: custom.domain" http://<IP>

# SMB/FTP Enumeration
nmap --script smb-enum-shares,smb-enum-users -p 139,445 <IP>
nmap --script ftp-anon -p 21 <IP>

# SNMP Enumeration
onesixtyone -c community.txt <IP>
snmpwalk -c public -v1 <IP>

# Notes from Machines 111–120
# - Machines revealed a mix of HTTP, FTP, and SMB services during scans.
# - Multiple machines exposed sensitive files via open directories or misconfigured virtual hosts.
# - Some targets used older versions of Apache/Nginx detectable via banner grabbing.
```