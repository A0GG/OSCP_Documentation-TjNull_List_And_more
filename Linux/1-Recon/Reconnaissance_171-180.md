## 🔍 Reconnaissance (Machines 171–180)

### Common Recon Techniques

```bash
nmap -p- --min-rate 10000 <IP>               # Full TCP port scan
nmap -p <open_ports> -sCV -oA targeted <IP>  # Script and version scan
whatweb http://<IP>                          # Identify web technologies
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```

### Additional Techniques Observed

```bash
curl -I http://<IP>                          # Grab HTTP headers
dig <domain> any                             # Enumerate DNS records
nslookup <domain>                            # Name server lookup
whois <domain>                               # WHOIS for domain ownership
```

### Notes from Machines 171–180

- Multiple machines used custom web ports (e.g., 8000, 8081).
- DNS enumeration on a few targets revealed hidden subdomains used for lateral movement.
- `robots.txt` and `server-status` were commonly exposed.
- WHOIS information hinted at development/internal environments in 2 machines.
- nmap scripts like `http-enum`, `ftp-anon`, and `smb-os-discovery` provided key insights.
