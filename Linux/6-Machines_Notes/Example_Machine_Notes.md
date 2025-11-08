
## 🗒️ Example Machine Notes (Generic Knowledge Base – First 10 Machines)

---

### 🐚 Machine 1
- Found `/admin.php` → WonderCMS → Exploited `CVE-2020-25213` (config leak → RCE)  
- Reverse shell uploaded via config abuse  
- PrivEsc: Log injection to escalate to root

---

### 🐚 Machine 2
- Discovered WordPress site via WhatWeb  
- SQL Injection in login form → Admin dashboard access  
- Found SSH private key → Logged in via SSH  
- PrivEsc via `sudo /usr/bin/python3` (NOPASSWD)

---

### 🐚 Machine 3
- Command injection on form input → Reverse shell triggered  
- Gained low-priv shell  
- PrivEsc using `sudo /bin/nmap` interactive mode to spawn root shell

---

### 🐚 Machine 4
- LFI via `/uploads` → Read `/etc/passwd`, gathered users  
- Found credentials inside exposed logs  
- PrivEsc: `sudo /bin/bash` available without password

---

### 🐚 Machine 5
- Classic SQLi in login → Admin panel compromise  
- User config dump revealed credentials  
- PrivEsc via Python interactive shell (`sudo /usr/bin/python3`)

---

### 🐚 Machine 6
- `CGI` command injection in `/cgi-bin/script.sh`  
- Shell via `curl` reverse payload  
- `sudo /bin/bash` allowed for root escalation

---

### 🐚 Machine 7
- Gobuster found `/admin`  
- Login page vulnerable to LFI  
- Gained creds via `/proc/self/environ` exposure  
- PrivEsc using `sudo /bin/sh`

---

### 🐚 Machine 8
- Login page SQLi → Admin panel  
- Found image upload feature  
- Uploaded `.php` shell disguised as `.jpg`  
- Rooted via `sudo /bin/bash`

---

### 🐚 Machine 9
- PHP form injection → Reverse shell back  
- Found NOPASSWD sudo on `/bin/bash`  
- Root shell executed directly

---

### 🐚 Machine 10
- RCE in file upload via web app  
- Uploaded web shell in `.php` disguised format  
- Escalated via `sudo python` trick
