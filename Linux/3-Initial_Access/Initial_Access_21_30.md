## 🔓 Initial Access (Machines 21–30)

```bash
# Machine: PG - Clue
Found exposed FTP service → Anonymous login allowed
Downloaded user.txt and possible credentials
Used credentials for SSH access

# Machine: PG - Extplorer
Extplorer file manager found on web interface
Used path traversal to read config and obtain credentials
Logged in via SSH with leaked creds

# Machine: PG - Postfish
PHP file upload vulnerability exploited for web shell
Gained initial shell as www-data
Escalated with leaked SSH key

# Machine: PG - Hawat
Public Jenkins interface with script console enabled
Ran Groovy reverse shell script → gained shell access

# Machine: PG - Walla
Exposed Samba shares
Found backup zip containing DB credentials
Used creds for database login → found reusable SSH creds

# Machine: PG - pc
PHP injection via eval() parameter in custom CMS
Sent reverse shell payload → connected back to attacker box

# Machine: PG - Sorcerer
Web application had default login (admin:admin)
Logged in and uploaded PHP reverse shell via admin panel

# Machine: PG - Sybaris
CMS had SSRF → leaked internal service running SSH
Enumerated internal creds and reused on main login

# Machine: PG - Peppo
LFI → leaked Apache config
Used config to identify accessible admin panel
Logged in and used plugin feature to upload shell

# Machine: PG - Hunit
Exposed SVN repository
Recovered sensitive credentials from .svn/entries
Used credentials for SSH access
```

---

### 🗒️ Example Notes

- Multiple machines used public tools like Jenkins or SVN without auth
- LFI + config file = common combination to extract passwords
- File upload & reverse shells remained popular for initial foothold