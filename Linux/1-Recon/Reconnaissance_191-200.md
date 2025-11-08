
## 🔍 Reconnaissance (Machines 191-200)

### Nmap Scans

```bash
nmap -p- --min-rate 10000 <IP>              # Fast full port scan  
nmap -p <ports> -sCV -oA scan <IP>          # Service/version detection  
nmap -T4 -A -v <IP>                        # Aggressive scan with OS detection and versioning  
nmap -p 80,443 -sV <IP>                    # Scan for HTTP/HTTPS services  
```

### Service Enumeration

```bash
nmap -sV -p <port> <IP>                    # Service version enumeration  
nmap --script=http-enum <IP>                # HTTP service enumeration script  
nmap -p 21,22,23,25,110,443 --script=default <IP>  # Default service enumeration script  
```

### CMS/Tech Stack Identification

```bash
whatweb http://<IP>                        # CMS/tech stack identification  
wappalyzer http://<IP>                     # Web application analysis  
```

### Directory Bruteforce

```bash
gobuster dir -u http://<IP> -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt   # Directory brute-forcing  
dirbuster -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt     # Alternate brute-forcing tool  
```

### Virtual Host Discovery

```bash
curl -I http://<IP>/robots.txt               # Check for additional subdomains or virtual hosts  
curl -I http://<IP>/server-status            # Check for exposed server status or configuration files  
```

### DNS Interrogation

```bash
dig <domain>                                 # Query DNS for domain information  
nslookup <domain>                            # Get the IP for the domain  
```

### Banner Grabbing

```bash
nc -v <IP> <Port>                            # Banner grabbing for service identification  
telnet <IP> <Port>                          # Telnet for banner grabbing  
curl -I http://<IP>                         # Get headers for HTTP services  
```

### Whois Lookup

```bash
whois <IP>                                   # Whois lookup for IP information  
whois <domain>                               # Whois lookup for domain information  
```

### CVE Reference Table

| Software         | CVE ID         | Vulnerability                        | Exploit Link                         |  
|------------------|----------------|--------------------------------------|--------------------------------------|  
| WordPress 5.1    | CVE-2019-6340  | Remote code execution via REST API   | Exploit-DB 48414                     |  
| Joomla 3.9.14    | CVE-2019-17659 | SQL Injection in com_content         | Exploit-DB 48577                     |  
| Drupal 7.72      | CVE-2020-13671 | SQL Injection via user registration  | Exploit-DB 49102                     |  
| Apache Struts 2  | CVE-2017-5638  | Remote code execution via OGNL        | Exploit-DB 40999                     |  

### Example Machine Notes (For your personal reference only)

**Recon Target 1:**

- Found open ports 80, 443, and 8080 → Running Apache 2.4.29  
- Service version detection → Apache 2.4.29 and OpenSSL 1.0.2g found  
- Recon Target 2:  
- Found open port 22 → Running SSH → Version 7.2  
- WhatWeb results: WordPress CMS detected → Further enumeration on wp-login.php  
