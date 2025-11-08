## 🔍 Reconnaissance (Machines 31–40)

```bash
# Fast port scanning and service detection
nmap -p- --min-rate 10000 <IP>
nmap -p <open-ports> -sCV -oA scan <IP>
nmap -T4 -A -v <IP>

# HTTP/HTTPS enumeration
whatweb http://<IP>
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
dirb http://<IP> /usr/share/wordlists/dirb/common.txt

# DNS enumeration (for DNS-exposed machines)
nslookup <target-domain>
dig <target-domain>
whois <target-domain>

# FTP, SSH, SMB enumeration
nmap -p 21,22,445 --script=banner,vuln <IP>
enum4linux-ng <IP>
smbclient -L //<IP>/ -N

# SNMP and LDAP discovery (for internal boxes)
nmap -sU -p 161 <IP> --script=snmp-info
nmap -sT -p 389 <IP> --script=ldap-rootdse

# Banner grabbing and service fingerprinting
nc -v <IP> <port>
curl -I http://<IP>
```

### Observations:
- Machines in this range include internal services (LDAP, SMB, SNMP) exposed for enumeration.
- Most boxes followed typical web + system service exposure (HTTP + SSH/SMB).
- Some web apps were hosted on non-standard ports (e.g., 8080, 5000).
- CMS detections included WordPress, Joomla, and custom-built apps.
