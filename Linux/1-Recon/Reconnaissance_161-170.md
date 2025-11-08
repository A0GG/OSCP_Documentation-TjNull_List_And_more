## 🔍 Reconnaissance (Machines 161–170)

### Tools & Techniques Used

```bash
nmap -p- --min-rate 10000 <IP>                    # Fast full port scan
nmap -sC -sV -oA full_scan <IP>                   # Default scripts and version detection
nmap --script vuln -p <port> <IP>                 # Vulnerability scan on detected ports
whatweb http://<IP>                               # Identify technologies and frameworks
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
ffuf -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
nikto -h http://<IP>                              # Web server vulnerability scan
curl -I http://<IP>                               # Grab HTTP headers
nslookup <domain> && dig <domain> any             # DNS recon
whois <domain>                                     # Domain registration info
```

### Common Findings

- Identification of SSH, HTTP, and HTTPS services across machines
- Web technologies included Apache, Nginx, PHP, WordPress, and Node.js
- Gobuster revealed hidden directories such as `/backup`, `/dev`, `/uploads`, and `/config`
- DNS and whois revealed internal hostnames and subdomains
- Nikto identified outdated web servers with known vulnerabilities
