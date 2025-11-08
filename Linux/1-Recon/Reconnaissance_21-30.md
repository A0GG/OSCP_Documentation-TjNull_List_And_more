## 🔍 Reconnaissance (Machines 21–30)

### Nmap & Port Scanning

```bash
nmap -p- --min-rate 10000 <IP>                   # Fast full TCP port scan
nmap -p <ports> -sCV -oA full_scan <IP>          # Service/version detection
nmap -T4 -A -v <IP>                              # Aggressive scan
```

### Service and Web Recon

```bash
whatweb http://<IP>                              # Tech stack identification
wappalyzer http://<IP>                           # Alternative tech analysis
curl -I http://<IP>                              # Inspect HTTP headers
```

### Directory & VHost Enumeration

```bash
gobuster dir -u http://<IP> -w <wordlist> -x php,html,txt
ffuf -u http://<IP>/FUZZ -w <wordlist> -e .php,.html,.txt
```

### DNS & OSINT

```bash
nslookup <domain>
dig <domain> any
whois <domain>
```

### Banner Grabbing & Basic Enumeration

```bash
nc -nv <IP> <port>
telnet <IP> <port>
```

---

> ✍️ This section compiles Reconnaissance data across machines 21 to 30, excluding redundancies already covered in previous machines.
