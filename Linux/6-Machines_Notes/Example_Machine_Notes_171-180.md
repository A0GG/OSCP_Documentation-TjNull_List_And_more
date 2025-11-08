
# 🗒️ Example Machine Notes (Machines 171–180)

---

## Machine 171
- Found `/admin` login page.
- Bypassed login using SQL injection.
- Gained access to admin panel and uploaded reverse shell.
- Privilege escalation via SUID binary `/usr/bin/python3`.

## Machine 172
- Exposed `/uploads` directory with PHP shell.
- Enumerated users from `/etc/passwd`.
- Used `sudo -l` to identify NOPASSWD command: `sudo perl`.

## Machine 173
- Found default credentials `admin:admin` on login form.
- Uploaded shell through image upload feature.
- Escalated using writable `/etc/passwd`.

## Machine 174
- Discovered CMS with outdated plugin.
- Plugin vulnerable to RCE.
- Escalated via `sudo /usr/bin/find`.

## Machine 175
- Identified exposed `.git` directory.
- Extracted credentials from source code.
- Escalated via LD_PRELOAD trick on custom binary.

## Machine 176
- DNS enumeration revealed hidden subdomain.
- Subdomain had exposed config with DB creds.
- Used SQL creds to get shell and escalated via cronjob hijack.

## Machine 177
- CMS exploit led to shell upload.
- Found root flag in another user’s home dir with read permission.
- Escalated using writable sudo script.

## Machine 178
- Port 5000 revealed Flask web app.
- RCE via insecure deserialization.
- Escalation through writable `/etc/shadow`.

## Machine 179
- Found LFI in PHP script.
- Poisoned log file and triggered reverse shell.
- Used `capsh` capabilities for escalation.

## Machine 180
- Gobuster found `/backup.zip`.
- Extracted password and used to SSH in.
- Escalated via kernel exploit.
