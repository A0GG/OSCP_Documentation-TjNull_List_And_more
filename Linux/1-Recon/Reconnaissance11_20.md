## 🔍 Reconnaissance (Machines 11–20)

```bash
# Nmap Full Port Scan & Version Detection
nmap -p- --min-rate 10000 <IP>            # Fast full port scan
nmap -p <discovered_ports> -sCV -oA scan <IP>  # Service/version detection

# Aggressive Scan (OS, Traceroute, Scripts)
nmap -A -T4 <IP>

# Web Tech Stack Enumeration
whatweb http://<IP>
wappalyzer http://<IP>

# Directory Brute-Force
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.txt,.bak

# DNS & Subdomain Enumeration
dig <domain>
nslookup <domain>
whois <domain>
host -t ns <domain>

# Banner Grabbing
nc -v <IP> <Port>
telnet <IP> <Port>
curl -I http://<IP>

# Service-specific Enum
nmap --script=http-enum -p80 <IP>
nmap --script=smb-enum-shares -p445 <IP>
nmap --script=ftp-anon -p21 <IP>
```

### Notes (Machines 11–20 Specific Recon):

- Added `ffuf` and `dirbuster` variations for deeper directory brute-force.
- Many machines exposed additional services (e.g., Redis, SNMP, FTP), requiring extra NSE scripts.
- DNS-based recon yielded internal subdomains in some cases.
- Some services displayed useful headers in response to `curl -I` requests (e.g., Apache, PHP versions).
