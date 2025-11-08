## 🔓 Initial Access (Machines 151–160)

```bash
# Machine 151
Found WordPress login → Used wpscan to enumerate users  
Discovered vulnerable plugin → Exploited for RCE

# Machine 152
Found /phpinfo.php → Leak of internal path  
Used LFI to disclose credentials from logs

# Machine 153
Discovered login page with SQLi  
Bypassed login and uploaded reverse shell

# Machine 154
Upload functionality allowed .phtml files  
Uploaded shell.phtml → Triggered reverse shell

# Machine 155
Found exposed admin panel  
Default creds: admin:admin → Shell upload option

# Machine 156
Identified CMS Made Simple  
Used known exploit with disclosed credentials

# Machine 157
Jenkins server accessible without auth  
Created build job to execute reverse shell

# Machine 158
Tomcat manager accessible → Used default credentials  
Uploaded war file → Gained shell

# Machine 159
Found /backup.zip → Extracted database with creds  
Used creds for SSH login

# Machine 160
Detected vulnerable webmail client  
Used CVE-2021-XXXXX → Auth bypass → Shell access
```
