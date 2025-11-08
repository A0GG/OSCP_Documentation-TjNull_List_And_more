## 🔓 Initial Access (Machines 51–60)

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

### 📋 CVE Reference Table

| Software         | CVE ID         | Vulnerability                          | Exploit Link                         |
|------------------|----------------|----------------------------------------|--------------------------------------|
| Drupal           | CVE-2018-7600  | Remote Code Execution                  | https://www.exploit-db.com/exploits/44449 |
| WordPress Plugin | CVE-2021-24284 | Arbitrary File Upload in wpDiscuz      | https://www.exploit-db.com/exploits/50001 |
| Joomla           | CVE-2015-8562  | RCE via User-Agent header              | https://www.exploit-db.com/exploits/39033 |
```

Let me know if you want to adjust or expand this section!
```
