## 🔍 Reconnaissance (Machines 181–190)

```bash
nmap -p- --min-rate 10000 <IP>                     # Fast full port scan  
nmap -p <ports> -sCV -oA scan <IP>                 # Version and script scan  
nmap -T4 -A -v <IP>                                # Aggressive scan with OS detection  
whatweb http://<IP>                                # Identify web technologies  
gobuster dir -u http://<IP> -w <wordlist> -x php,html,txt  # Brute-force directories  
nikto -h http://<IP>                               # Web server vulnerability scan  
curl -I http://<IP>                                # Grab HTTP headers  
dirsearch -u http://<IP> -e php,html,txt           # Recursive directory bruteforce  
ffuf -u http://<IP>/FUZZ -w <wordlist> -e .php,.html,.txt # Fuzz for files and dirs  
dig <domain>                                       # DNS enumeration  
nslookup <domain>                                  # Resolve domain name  
whois <domain>                                     # Domain info  
```

### Common Findings:
- Web servers on ports 80, 8080, and 443 commonly identified.
- Technologies like Apache, Nginx, PHP, WordPress, and Node.js detected using WhatWeb.
- DNS and WHOIS used to discover hidden subdomains and domain owner details.
- Gobuster and Dirsearch often revealed paths like `/admin`, `/uploads`, `/backup`.

### Example Recon Notes:
- **Machine Alpha**: Found ports 22/80/3306 open, exposed `/phpmyadmin`, OS fingerprint Ubuntu.
- **Machine Beta**: Subdomain `dev.site.com` discovered using `dig` and virtual host brute-force.
- **Machine Gamma**: HTTP headers indicated Apache/2.4.41 with PHP/7.4.3 on Ubuntu.
