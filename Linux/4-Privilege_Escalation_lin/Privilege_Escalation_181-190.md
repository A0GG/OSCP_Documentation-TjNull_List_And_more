
# Privilege Escalation (Machines 181-190)

This file contains the privilege escalation phase for the machines in the range of 181 to 190.

---

### Machine 181:
- **Initial Enumeration**:
  - `sudo -l`: User can run `/bin/bash` with no password.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Ran `/bin/bash` to spawn a shell as root.

---

### Machine 182:
- **Initial Enumeration**:
  - `sudo -l`: User can execute `/bin/nmap` with no password.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Ran `nmap` with elevated privileges, escalated to root.

---

### Machine 183:
- **Initial Enumeration**:
  - `sudo -l`: User has permission to run `/usr/bin/python3` with no password.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Used Python to spawn a shell as root.

---

### Machine 184:
- **Initial Enumeration**:
  - `sudo -l`: User can run `/bin/sh` with no password.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Spawned a root shell using `sudo /bin/sh`.

---

### Machine 185:
- **Initial Enumeration**:
  - `sudo -l`: User has permission to run `/usr/bin/nmap` as root.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Ran `nmap` with elevated privileges and escalated to root.

---

### Machine 186:
- **Initial Enumeration**:
  - `sudo -l`: User can execute `/usr/bin/python3` with no password.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Ran a Python reverse shell to escalate to root.

---

### Machine 187:
- **Initial Enumeration**:
  - `sudo -l`: User can run `/bin/bash` with no password.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Spawned a shell using `sudo /bin/bash`.

---

### Machine 188:
- **Initial Enumeration**:
  - `sudo -l`: User has permission to run `/usr/bin/awk` as root.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Used `awk` to execute a command with root privileges and escalated to root.

---

### Machine 189:
- **Initial Enumeration**:
  - `sudo -l`: User can run `/bin/bash` as root.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Spun up a root shell with `sudo /bin/bash`.

---

### Machine 190:
- **Initial Enumeration**:
  - `sudo -l`: User has permission to run `/usr/bin/python3` as root.
  - `find / -perm -4000 -type f`: Found SUID binaries.
  - `getcap -r /`: Checked for Linux capabilities.

- **Exploitation**:
  - Ran a Python reverse shell to escalate to root.

---
