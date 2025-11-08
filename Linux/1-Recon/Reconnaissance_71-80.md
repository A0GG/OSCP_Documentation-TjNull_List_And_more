## 🔍 Reconnaissance (Machines 71–80)

```bash
# Machine 71
nmap -p- --min-rate 10000 10.10.10.71
nmap -p 22,80 -sCV -oA scan_71 10.10.10.71
whatweb http://10.10.10.71

# Machine 72
nmap -sT -p- 10.10.10.72
nmap -p 80,443 -sV 10.10.10.72
gobuster dir -u http://10.10.10.72 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Machine 73
nmap -sC -sV -oA nmap_73 10.10.10.73
curl -I http://10.10.10.73

# Machine 74
nmap -p- --min-rate 5000 10.10.10.74
dig any example74.com
nslookup example74.com

# Machine 75
nmap -sS -T4 10.10.10.75
whatweb http://10.10.10.75
whois example75.com

# Machine 76
nmap -A -T4 -p- 10.10.10.76
gobuster dir -u http://10.10.10.76 -w common.txt -x php,txt

# Machine 77
nmap -sV -sC 10.10.10.77
curl -I http://10.10.10.77/robots.txt

# Machine 78
nmap -Pn -p- 10.10.10.78
nmap -sV -p 22,80,3306 10.10.10.78

# Machine 79
nmap -p- -T4 10.10.10.79
dirsearch -u http://10.10.10.79

# Machine 80
nmap -sT -A -v 10.10.10.80
wappalyzer http://10.10.10.80
```