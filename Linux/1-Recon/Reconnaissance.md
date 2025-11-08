
## 🔍 Reconnaissance

```bash
# Nmap - Initial Scanning
nmap -p- --min-rate 10000 <IP>              # Fast port scan for all ports
nmap -sC -sV -oN nmap_scan.txt <IP>         # Default script and version scan
nmap -T4 -A -v <IP>                         # Aggressive scan with OS detection and versioning
nmap -sU -p- <IP>                           # UDP port scan

# Gobuster / Dirb - Web Directories
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
dirb http://<IP>                            # Simple directory brute-force

# DNS & Subdomain Enumeration
dig <domain> any                            # Get all DNS records
nslookup <domain>                           # DNS lookup
whois <domain>                              # Domain ownership
ffuf -u http://<IP>/FUZZ -w wordlist.txt    # Directory fuzzing

# Web Enumeration Tools
whatweb http://<IP>                         # Identify technologies on the site
wappalyzer http://<IP>                      # Another tool for tech stack
nikto -h http://<IP>                        # Web vulnerability scanner

# SMB Enumeration
nmap --script smb-enum-shares.nse -p 445 <IP>   # SMB share enumeration
enum4linux-ng <IP>                              # SMB/NetBIOS enum
smbclient -L //<IP>                             # List shares anonymously

# FTP Enumeration
ftp <IP>                                       # Try anonymous login
nmap --script=ftp-anon,ftp-bounce -p 21 <IP>

# SNMP Enumeration
onesixtyone -c community.txt <IP>              # Check for default SNMP strings
snmpwalk -v2c -c public <IP>                   # SNMP enum using public string

# General Information Gathering
curl -I http://<IP>                            # Check headers
nc -nv <IP> <PORT>                             # Manual banner grab
```

---

### 📋 CVE Reference Table

```markdown
| Service       | CVE ID         | Vulnerability Summary                      | Exploit Ref               |
|---------------|----------------|---------------------------------------------|---------------------------|
| Apache 2.4.49 | CVE-2021-41773 | Path traversal → RCE                        | Exploit-DB 50404          |
| Samba         | CVE-2017-7494  | Remote code execution via writable share    | Exploit-DB 42084          |
| vsftpd        | CVE-2011-2523  | Backdoor command execution                  | Exploit-DB 17491          |
```

---

### 🗒️ Recon Notes (Generic)

```markdown
- Found ports 22, 80, 443 → Basic SSH and HTTP/HTTPS services.
- Discovered /admin.php and /uploads via Gobuster.
- Apache version 2.4.49 vulnerable to CVE-2021-41773 → path traversal.
- FTP allowed anonymous login → accessed files.
- Enumerated SMB shares and userlist from enum4linux.
- SNMP public string found, used snmpwalk to dump processes.
```
