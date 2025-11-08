
# Example Machine Notes (Machines 181–190)

## Example Machine Notes

### Machine 181
- **Exploit**: Local File Inclusion (LFI) vulnerability found on `/admin.php` page
- **Privilege Escalation**: Found Sudoers misconfiguration allowing user to execute `/bin/bash` as root without a password
- **Method**: Injected payload into `file` parameter to access sensitive files, escalated privileges using `sudo /bin/bash`

### Machine 182
- **Exploit**: SQL Injection vulnerability in login form
- **Privilege Escalation**: Found user with sudo access to `/usr/bin/python3` without a password
- **Method**: Used SQL Injection to bypass authentication, then escalated privileges with Python script execution

### Machine 183
- **Exploit**: Command Injection vulnerability in the `ping` script
- **Privilege Escalation**: Sudo access to `/bin/nmap` found
- **Method**: Used command injection to get reverse shell, escalated privileges with nmap to root

### Machine 184
- **Exploit**: XSS vulnerability on login page
- **Privilege Escalation**: Discovered user can run `/usr/bin/bash` via sudo
- **Method**: Used XSS to steal session cookies, escalated privileges using sudo

### Machine 185
- **Exploit**: Directory Traversal vulnerability in file upload functionality
- **Privilege Escalation**: Found that user can execute arbitrary commands as root via sudoers misconfig
- **Method**: Used directory traversal to upload shell, escalated privileges using `sudo /bin/bash`

### Machine 186
- **Exploit**: Insecure direct object reference (IDOR) vulnerability
- **Privilege Escalation**: Misconfigured Sudoers allowing the execution of `/bin/bash` without a password
- **Method**: Exploited IDOR to gain access to restricted files, escalated privileges using sudoers misconfig

### Machine 187
- **Exploit**: Vulnerable file upload allowing PHP shell upload
- **Privilege Escalation**: Found sudo access for `/usr/bin/perl`
- **Method**: Uploaded PHP shell, escalated privileges by executing Perl with sudo

### Machine 188
- **Exploit**: Remote Code Execution (RCE) via vulnerable service
- **Privilege Escalation**: Sudo access found for `/bin/bash`
- **Method**: Triggered RCE on vulnerable service, escalated privileges using sudo

### Machine 189
- **Exploit**: Command Injection vulnerability in the `ping` functionality
- **Privilege Escalation**: Misconfigured sudo allowing user to execute `/bin/bash`
- **Method**: Exploited command injection, escalated privileges to root using `sudo /bin/bash`

### Machine 190
- **Exploit**: Open Redirect vulnerability found in user input processing
- **Privilege Escalation**: Discovered user can run arbitrary commands with sudo without a password
- **Method**: Used open redirect to bypass authentication, escalated privileges via sudo
