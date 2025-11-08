## 🔍 Reconnaissance (Machines 51–60)

```bash
# Machine: Clue (PG)
nmap -sC -sV -oN clue.nmap 192.168.61.100
gobuster dir -u http://192.168.61.100 -w /usr/share/wordlists/dirb/common.txt

# Machine: Extplorer (PG)
nmap -p- --min-rate 10000 -oN extplorer.full 192.168.57.100
nmap -sC -sV -p 21,80 -oN extplorer.nmap 192.168.57.100
curl -I http://192.168.57.100/

# Machine: Postfish (PG)
nmap -p- -T4 -oN postfish.full 192.168.61.104
nmap -sC -sV -p 80,22 -oN postfish.nmap 192.168.61.104

# Machine: Hawat (PG)
nmap -p- 192.168.58.100 --min-rate 5000 -oN hawat.full
nmap -sC -sV -p 22,80 -oN hawat.nmap 192.168.58.100
whatweb http://192.168.58.100

# Machine: Walla (PG)
nmap -p- --min-rate 10000 -oN walla.full 192.168.56.100
nmap -sC -sV -p 80,22 -oN walla.nmap 192.168.56.100
gobuster dir -u http://192.168.56.100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Machine: pc (PG)
nmap -T4 -p- -oN pc.full 192.168.57.100
nmap -sC -sV -p 22,80,445 -oN pc.nmap 192.168.57.100
dirb http://192.168.57.100

# Machine: Sorcerer (PG)
nmap -p- --min-rate 10000 -oN sorcerer.full 192.168.56.110
nmap -sC -sV -p 80,22 -oN sorcerer.nmap 192.168.56.110
curl -I http://192.168.56.110

# Machine: Sybaris (PG)
nmap -p- -T4 192.168.60.100 -oN sybaris.full
nmap -sC -sV -p 80,22 -oN sybaris.nmap 192.168.60.100
gobuster dir -u http://192.168.60.100 -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Machine: Peppo (PG)
nmap -p- --min-rate 10000 192.168.59.100 -oN peppo.full
nmap -sC -sV -p 22,80 -oN peppo.nmap 192.168.59.100
whatweb http://192.168.59.100

# Machine: Hunit (PG)
nmap -T4 -p- -oN hunit.full 192.168.58.110
nmap -sC -sV -p 22,80 -oN hunit.nmap 192.168.58.110
```
