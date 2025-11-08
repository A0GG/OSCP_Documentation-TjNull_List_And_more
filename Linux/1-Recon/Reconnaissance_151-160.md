## 🔍 Reconnaissance (Machines 151–160)

```bash
# Nmap scanning
nmap -p- --min-rate 10000 <IP>            # Fast full port scan
nmap -p <ports> -sCV -oA full_scan <IP>   # Version detection and script scan
nmap -T4 -A -v <IP>                       # Aggressive scan with OS detection

# Directory brute-forcing
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

# Web technology identification
whatweb http://<IP>
wappalyzer http://<IP>

# DNS enumeration
dig <domain> any
nslookup <domain>
whois <domain>

# Virtual host discovery
ffuf -u http://<IP> -H "Host: FUZZ.example.com" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt

# Banner grabbing
nc -v <IP> <port>
curl -I http://<IP>
telnet <IP> <port>

# SMB/FTP/SMTP enumeration
nmap --script smb-enum-shares.nse,smb-enum-users.nse -p 445 <IP>
enum4linux <IP>
nmap --script ftp-anon,ftp-bounce -p 21 <IP>
nmap --script smtp-commands -p 25 <IP>
```
