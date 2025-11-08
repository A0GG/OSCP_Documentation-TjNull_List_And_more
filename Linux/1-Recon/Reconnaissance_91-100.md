## 🔍 Reconnaissance (Machines 91–100)

```bash
# General Port Scanning
nmap -p- --min-rate 10000 <IP>                 # Fast full port scan
nmap -sC -sV -p- <IP> -oN full_scan.txt         # Default scripts and version detection
nmap -T4 -A <IP>                                # Aggressive scan for OS and services

# Service-Specific Enumeration
nmap -p 21 --script=ftp-anon <IP>               # Check for anonymous FTP access
nmap --script smb-enum-shares.nse -p 445 <IP>   # Enumerate SMB shares
nmap --script http-enum,http-title -p 80 <IP>   # HTTP service detection

# Web Recon
whatweb http://<IP>                             # Identify web technologies
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
nikto -host <IP>                                # Vulnerability scanner for web servers

# DNS and Hostname Enumeration
nslookup <domain>
dig <domain> any
host -a <domain>

# Banner Grabbing & Service Fingerprinting
nc -nv <IP> <port>                              # Manual banner grabbing
curl -I http://<IP>                             # Get HTTP response headers

# Virtual Hosts / VHosts
ffuf -u http://<IP> -H "Host: FUZZ.<domain>" -w subdomains.txt  # Virtual host fuzzing
```

### Notes
- Most machines had web servers and SSH exposed (ports 80 and 22).
- Multiple instances used CMS systems like WordPress and Joomla.
- FTP and SMB enumeration yielded useful foothold information on several targets.
- Aggressive scans (nmap -A) helped uncover hidden services or outdated versions.
