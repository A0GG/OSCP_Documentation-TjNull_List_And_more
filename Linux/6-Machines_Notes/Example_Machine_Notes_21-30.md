## 🗒️ Example Machine Notes (Machines 21–30)

---

### Machine 21 - Pandora
- Recon: Found ports 22 and 80 open. Discovered Pandora FMS login page on port 80.
- Web Enum: Found default credentials working (admin:pandora). Identified potential RCE through module creation.
- Exploitation: Used authenticated RCE (Pandora FMS CVE-2021-32099) to get shell.
- PrivEsc: Found SUID binary and abused it to escalate to root.

---

### Machine 22 - OpenAdmin
- Recon: Found ports 22, 80. Apache server hosted a site with /music/ subdirectory.
- Web Enum: Found reuse of SSH creds through exposed username in notes.
- Exploitation: Gained shell through SSH using harvested creds.
- PrivEsc: Used enumeration to find user was part of sudo group and misconfigured script allowed root shell.

---

### Machine 23 - Precious
- Recon: Ruby-based web service running on port 80.
- Web Enum: Identified YAML deserialization vector.
- Exploitation: Crafted malicious YAML payload to gain code execution.
- PrivEsc: Found backup script with writable permissions leading to privilege escalation.

---

### Machine 24 - Busqueda
- Recon: PHPMyAdmin running on port 80.
- Web Enum: Found credentials in source code of index.php.
- Exploitation: Accessed DB, extracted user credentials and reused for SSH.
- PrivEsc: Found binary with SUID bit set and used to gain root.

---

### Machine 25 - Monitored
- Recon: Web dashboard and SSH on standard ports.
- Web Enum: Exposed metrics endpoint revealed local credentials.
- Exploitation: SSH access with exposed creds, pivoted to another user via su.
- PrivEsc: Used kernel exploit based on OS version.

---

### Machine 26 - BoardLight
- Recon: Found Git repo exposed in .git directory.
- Web Enum: Reconstructed source code and found hardcoded creds.
- Exploitation: Used hardcoded creds for login and RCE.
- PrivEsc: Found a cronjob executing writable script.

---

### Machine 27 - Magic
- Recon: Found image upload portal vulnerable to file upload bypass.
- Web Enum: .htaccess and double extension trick worked (.php.jpg).
- Exploitation: Web shell executed and reverse shell obtained.
- PrivEsc: Enumerated system and found SUID Python binary used to escalate.

---

### Machine 28 - Help
- Recon: Apache default page and FTP server.
- Web Enum: Anonymous FTP access gave access to backup files.
- Exploitation: Recovered DB creds from backup and reused.
- PrivEsc: Root access gained via writable cronjob.

---

### Machine 29 - Editorial
- Recon: CMS exposed on HTTP service.
- Web Enum: Found known CVE for the CMS.
- Exploitation: Authenticated RCE chain led to shell.
- PrivEsc: Used logrotate script with improper permissions.

---

### Machine 30 - Builder
- Recon: CI/CD interface exposed (Jenkins).
- Web Enum: Discovered anonymous login to Jenkins.
- Exploitation: Jenkins script console RCE used for access.
- PrivEsc: Jenkins was running as root—direct shell access yielded root.
