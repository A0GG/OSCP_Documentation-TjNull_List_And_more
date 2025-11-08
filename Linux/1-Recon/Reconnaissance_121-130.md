## 🔍 Reconnaissance (Machines 121–130)

```bash
# Nmap Scans
nmap -p- --min-rate 10000 <IP>            # Fast full TCP port scan
nmap -p <ports> -sCV -oA full_scan <IP>   # Version and script scan on discovered ports
nmap -T4 -A -v <IP>                       # Aggressive scan with OS detection

# HTTP/HTTPS Enumeration
whatweb http://<IP>                       # Web tech fingerprinting
gobuster dir -u http://<IP> -w common.txt -x php,html,txt  # Directory brute-force

# DNS Enumeration
dig <domain> any                          # Find all DNS records
nslookup <domain>                         # Simple domain resolution
whois <domain>                            # Domain registration details

# Virtual Host Discovery
ffuf -u http://<IP>/ -H "Host: FUZZ.<domain>" -w subdomains.txt  # Subdomain fuzzing

# Service Specific Scans
nmap --script ftp-anon -p 21 <IP>         # Check for anonymous FTP
nmap --script=smb-enum-shares -p 445 <IP> # SMB share enumeration
nmap --script=http-title -p 80 <IP>       # HTTP titles
```

### Notes:

- Machine 121: Discovered exposed FTP service allowing anonymous access.
- Machine 122: Used whatweb and identified Apache Tomcat, redirected to port 8080.
- Machine 123: Web enumeration discovered `/monitoring` revealing system info.
- Machine 124: DNS zone transfer misconfigured, retrieved full zone records.
- Machine 125: Port 5985 WinRM open, verified with CrackMapExec.
- Machine 126: Port 10000 running Webmin, known to be exploitable.
- Machine 127: Enumerated SNMP with snmpwalk, exposed system descriptions.
- Machine 128: Found Elasticsearch instance on port 9200, no auth.
- Machine 129: Exposed Git repo found at /.git, pulled source code.
- Machine 130: Found VNC on 5901 with default password, possible GUI access.
