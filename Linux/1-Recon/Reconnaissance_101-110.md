## 🔍 Reconnaissance (Machines 101–110)

```bash
# Nmap Scans
nmap -p- --min-rate 10000 <IP>                      # Full TCP port scan
nmap -sC -sV -p <open-ports> -oN targeted_scan <IP>  # Service enumeration

# Directory Bruteforcing
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

# Web Tech Stack
whatweb http://<IP>
wappalyzer http://<IP>

# DNS Enumeration
dig <domain>
nslookup <domain>

# OSINT / WHOIS
whois <domain>

# Banner Grabbing
nc -nv <IP> <port>
curl -I http://<IP>

# Additional Enum Tools
nikto -host http://<IP>
```

### Notes:
- Most machines had common web services on ports 80 and 443.
- Several had FTP or SSH ports open (21, 22) that led to further access vectors.
- Gobuster frequently revealed `/admin`, `/backup`, and configuration directories.
- CMS detection helped identify WordPress, Joomla, and custom PHP frameworks.
