## 🗒️ Example Machine Notes (Machines 81–90)

**Machine 81 – 'Quackerjack'**
- Web service hosted on port 8080 revealed a custom admin panel.
- Command injection in the admin logs export function.
- Privilege escalation through cron job exploiting writable script.

**Machine 82 – 'Wombo'**
- WordPress installation with vulnerable plugin.
- LFI discovered in theme previewer.
- Gained shell via malicious plugin upload and escalated using NOPASSWD sudo binary.

**Machine 83 – 'Flu'**
- Found file upload endpoint with weak validation.
- Used .php5 extension to bypass and execute reverse shell.
- PrivEsc using vulnerable kernel CVE-2017-16995.

**Machine 84 – 'Roquefort'**
- SNMP enumeration leaked user credentials.
- SSH access using credentials; found binary with SUID.
- SUID binary exploited to spawn root shell.

**Machine 85 – 'Levram'**
- HTTP service leaked internal backup via directory traversal.
- Password found in config.php → SSH login.
- PrivEsc: sudo access to tcpdump allowed command execution.

**Machine 86 – 'MZEEAV'**
- CMS detected via WhatWeb; CVE matched and exploited for shell.
- User had sudo access to pip → Escalated to root using pip module.

**Machine 87 – 'LaVita'**
- Jenkins panel exposed.
- Gained access via Jenkins script console.
- Root escalation using writable init script.

**Machine 88 – 'Zipper'**
- SMB share contained sensitive files.
- Extracted credentials from database dump.
- Used SUID 'nmap' binary for privilege escalation.

**Machine 89 – 'Ochima'**
- Drupal CMS found; exploited CVE-2018-7600 (Drupalgeddon 2).
- Shell access obtained.
- Root via cron job abuse on writable script.

**Machine 90 – 'Fired'**
- File upload allowed .php3 → RCE achieved.
- MySQL password reused for SSH.
- PrivEsc using misconfigured Docker socket.

---

Each note was distilled from the original CTF writeup and formatted for Obsidian vault compatibility.
