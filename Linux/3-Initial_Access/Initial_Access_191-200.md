
## 🔓 Initial Access

### Common Vectors:
- CMS Exploits (e.g., WordPress, Joomla)
- File Upload Bypass (e.g., .php files disguised as images)
- SSH Credential Reuse (e.g., Bruteforce/Default credentials)
- RCE via Vulnerable Applications

```bash
curl http://<IP>/config.php | grep password  # Check for exposed configs
hashcat -m 0 hash.txt rockyou.txt           # Crack hashes
```

### Exploit for File Upload Bypass
- **Vuln:** File upload vulnerability in a web application
- **Exploit:** Used a .php file disguised as an image to gain access to the server

```bash
curl -F "file=@shell.php.jpg" http://<IP>/upload
```

### SSH Credential Reuse:
- **Vuln:** SSH credentials reused from previous scans or default credentials
- **Exploit:** Used credentials to log into the SSH service

```bash
ssh user@<IP> -p 2222
```

---

### CVE Reference Table:

| Software         | CVE ID         | Vulnerability                        | Exploit Link                         |
|------------------|----------------|--------------------------------------|--------------------------------------|
| WordPress 5.1    | CVE-2019-6340  | Remote code execution via REST API   | Exploit-DB 48414                     |
| Joomla 3.9.14    | CVE-2019-17659 | SQL Injection in com_content         | Exploit-DB 48577                     |
| Drupal 7.72      | CVE-2020-13671 | SQL Injection via user registration  | Exploit-DB 49102                     |
| Apache Struts 2  | CVE-2017-5638  | Remote code execution via OGNL       | Exploit-DB 40999                     |

---

### Example Machine Notes

**Machine 1 (IP: 192.168.1.1)**:
- Found exposed WordPress login page
- Exploited CVE-2019-6340 via REST API
- Gained shell access on the server

**Machine 2 (IP: 192.168.1.2)**:
- Discovered exposed file upload feature
- Uploaded a PHP shell file
- Gained access to the server
