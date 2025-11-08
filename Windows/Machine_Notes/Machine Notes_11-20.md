**Remote (HTB)**

- **Machine:** Remote
- **Initial Access:** Vulnerable web application (low-privilege user).
- **Credentials:** Administrator password (plaintext) decrypted from TeamViewer registry (`SecurityPasswordAES`).
- **Privilege Escalation:** Decrypting TeamViewer's stored Administrator password from the registry.
- **Key Tools/Techniques:** Registry inspection (`reg query`), TeamViewer static AES key decryption.
- **Outcome:** Administrator shell (via SMB or WinRM login).

**Buff (HTB)**

- **Machine:** Buff
- **Initial Access:** Unauthenticated file upload in Gym Management System (limited user).
- **Credentials:** None directly obtained for privilege escalation.
- **Privilege Escalation:** Buffer overflow in CloudMe Sync v1.11.2 (CVE-2018-7886) via port forwarding.
- **Key Tools/Techniques:** SSH tunneling/port forwarding, CloudMe exploit script.
- **Outcome:** SYSTEM shell.

**Love (HTB)**

- **Machine:** Love
- **Initial Access:** SSRF in Love PDF generator -> web shell (web-app user).
- **Credentials:** None directly obtained for privilege escalation.
- **Privilege Escalation:** Abuse of AlwaysInstallElevated policy (registry misconfiguration).
- **Key Tools/Techniques:** Malicious MSI payload creation (`msfvenom`), `msiexec`.
- **Outcome:** SYSTEM shell.

**SecNotes (HTB)**

- **Machine:** SecNotes
- **Initial Access:** Exploit in custom web application (user-level access).
- **Credentials:** Plaintext Administrator password found in WSL `.bash_history`.
- **Privilege Escalation:** Discovery of plaintext Administrator password in WSL bash history.
- **Key Tools/Techniques:** Accessing WSL filesystem, reading `.bash_history`.
- **Outcome:** Administrator shell (via RDP or WinRM login).

**Access (HTB)**

- **Machine:** Access
- **Initial Access:** FTP service -> outdated backup (user credentials).
- **Credentials:** Administrator credentials cached via `runas /savecred`, Administrator password decrypted from DPAPI blob (using Mimikatz).
- **Privilege Escalation:** Reusing saved Administrator credentials via `runas`, OR extracting and decrypting Administrator credentials from DPAPI.
- **Key Tools/Techniques:** `.lnk` file analysis, `runas`, DPAPI dumping (Mimikatz), DPAPI decryption (Mimikatz).
- **Outcome:** Administrator shell.

**Mailing (HTB)**

- **Machine:** Mailing
- **Initial Access:** Phishing (CVE-2024-21413) -> user `Maya`. LibreOffice vulnerability (CVE-2023-2255) -> LocalAdmin.
- **Credentials:** None directly obtained for final privilege escalation.
- **Privilege Escalation:** Abuse of `SeImpersonatePrivilege` with GodPotato exploit (from LocalAdmin context).
- **Key Tools/Techniques:** GodPotato exploit.
- **Outcome:** SYSTEM shell.

**Heist (HTB)**

- **Machine:** Heist
- **Initial Access:** Open SMB share -> configuration files -> cracked user passwords.
- **Credentials:** Plaintext Administrator password (reused from another account).
- **Privilege Escalation:** Password reuse (Administrator password was the same as another account).
- **Key Tools/Techniques:** Password cracking (hashcat, etc.), `evil-winrm`.
- **Outcome:** Administrator shell (direct login).

**Kevin (OffSec PG Practice)**

- **Machine:** Kevin
- **Initial Access:** N/A (Direct SYSTEM access via exploit).
- **Credentials:** N/A.
- **Privilege Escalation:** Remote buffer overflow in HP Power Manager (CVE-2009-3999).
- **Key Tools/Techniques:** Metasploit (`exploit/windows/http/hp_power_manager_formexport`).
- **Outcome:** SYSTEM shell (direct from exploit).

**Internal (OffSec PG Practice)**

- **Machine:** Internal
- **Initial Access:** N/A (Direct SYSTEM access via exploit).
- **Credentials:** N/A.
- **Privilege Escalation:** Remote SMBv2 "negotiate protocol" vulnerability (MS09-050 / CVE-2009-3103).
- **Key Tools/Techniques:** Metasploit (`exploit/windows/smb/ms09_050_smb2_negotiate`).
- **Outcome:** SYSTEM shell (direct from exploit).

**Algernon (OffSec PG Practice)**

- **Machine:** Algernon
- **Initial Access:** N/A (Direct SYSTEM access via exploit).
- **Credentials:** N/A.
- **Privilege Escalation:** .NET Remoting service RCE via insecure deserialization (CVE-2014-1806).
- **Key Tools/Techniques:** Public exploit script (Exploit-DB #49216).
- **Outcome:** SYSTEM shell (direct from exploit).