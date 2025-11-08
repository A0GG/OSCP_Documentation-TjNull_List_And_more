## 🔍 Reconnaissance (Machines 131–140)

```bash
# Nmap quick and aggressive scanning
nmap -p- --min-rate 10000 <IP>
nmap -sC -sV -oA full_scan <IP>

# Web technology and directory enumeration
whatweb http://<IP>
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# DNS enumeration and virtual hosts
nslookup <domain>
dig <domain> any
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<IP>/ -H "Host: FUZZ.<domain>"

# Banner grabbing and other services
curl -I http://<IP>
nc -vn <IP> <port>
enum4linux <IP>  # If SMB port is open

# SNMP
onesixtyone <IP>
snmpwalk -v2c -c public <IP> 1
```
