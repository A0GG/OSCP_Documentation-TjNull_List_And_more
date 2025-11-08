## 🔍 Reconnaissance (Machines 141–150)

### Port Scanning
```bash
nmap -p- --min-rate 10000 <IP>
nmap -p <open-ports> -sC -sV -oA nmap/target <IP>
```

### Web & HTTP Recon
```bash
whatweb http://<IP>
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

### DNS and Subdomain Enumeration
```bash
nslookup <domain>
dig <domain> any
whois <domain>
```

### Virtual Host Discovery
```bash
wfuzz -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<domain>" --hc 400 <IP>
```

### Banner Grabbing and Service Probing
```bash
nc -vn <IP> <port>
curl -I http://<IP>
```

### SMB Enumeration (if applicable)
```bash
smbclient -L //<IP> -N
enum4linux <IP>
```

### SNMP Enumeration (if applicable)
```bash
onesixtyone -c community.txt <IP>
snmpwalk -v 2c -c public <IP>
```

### FTP/SSH/SMTP Recon (if applicable)
```bash
hydra -L users.txt -P passwords.txt ftp://<IP>
hydra -L users.txt -P passwords.txt ssh://<IP>
nmap -p 25 --script smtp-enum-users <IP>
```
