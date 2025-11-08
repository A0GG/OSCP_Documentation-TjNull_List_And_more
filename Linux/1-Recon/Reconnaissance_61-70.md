## 🔍 Reconnaissance (Machines 61–70)

```bash
# Port Scanning & Service Detection
nmap -p- --min-rate 10000 <IP>              # Full port scan
nmap -sC -sV -oA nmap/initial <IP>          # Default scripts and version detection
nmap -sV -p- -T4 <IP>                       # Version detection with aggressive timing
nmap -sU -p- <IP>                           # UDP scan when needed

# Web Tech Stack Fingerprinting
whatweb http://<IP>
wappalyzer http://<IP>                     # Run via browser or CLI for stack insights

# Directory and File Brute-Forcing
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt
ffuf -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# DNS and Hostname Enumeration
dig <domain> any
nslookup <domain>
host -t cname <domain>
whois <domain>

# Virtual Host & Subdomain Enumeration
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<domain>" --hc 400 http://<IP>
vhostscan -t http://<IP>

# Header Inspection & Info Disclosure
curl -I http://<IP>
nikto -h http://<IP>                       # Web server vulnerability scan
curl http://<IP>/robots.txt
curl http://<IP>/crossdomain.xml

# Public Info / OSINT
theHarvester -d <domain> -b all
crt.sh query: %.domain.com                 # Search subdomains via public certs
```

### Notes (Highlights from Machines 61–70)

- Found non-standard ports (e.g., 1337, 8081) serving interesting services like Tomcat or Node.js.
- Certain boxes leaked directories like `/development`, `/test`, or `/dashboard` which helped with version fingerprinting.
- VHost enumeration revealed hidden admin portals (e.g., `dev.box.htb`, `admin.box.htb`) that were not part of initial Nmap results.
- One machine served an old Django app on port 8000 with `/admin/` exposed.
- Web headers gave away the app version or platform in some machines (Apache 2.2.22, PHP 5.3.29).