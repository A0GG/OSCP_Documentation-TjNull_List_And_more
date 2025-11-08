## 🔓 Initial Access (Machines 31–40)

```bash
# Common Exploitation Paths
- Exploited CMS platforms (WordPress, Joomla, Drupal) with known CVEs.
- Used exposed configuration files to extract credentials.
- Tested default credentials and common login bypasses.
- Uploaded PHP/ASPX web shells via misconfigured upload features.

# Examples
curl http://<IP>/config.php | grep password      # Find exposed DB credentials
ssh user@<IP> -p 2222                             # Try SSH access with reused credentials
```

### Notable Techniques
- File upload bypass using `.htaccess` + double extensions.
- SQL Injection to extract password hashes.
- Path traversal to download `wp-config.php` or `.env` files.
- Exploited outdated plugins and themes for RCE.

### Summary of Entry Points
| Machine | Vector Used              | Technique              |
| ------- | ------------------------ | ---------------------- |
| 31      | Joomla Admin Login       | Default credentials    |
| 32      | Drupal Exploit           | CVE-2018-7600          |
| 33      | Exposed config.php       | Password reuse         |
| 34      | File upload              | RCE with reverse shell |
| 35      | Auth bypass on login.php | Session manipulation   |
| 36      | WordPress plugin exploit | LFI to RCE             |
| 37      | Apache misconfig         | Directory traversal    |
| 38      | Jenkins                  | Script console RCE     |
| 39      | Node.js API              | Command injection      |
| 40      | Git repo leak            | Recovered admin creds  |
```

# Done