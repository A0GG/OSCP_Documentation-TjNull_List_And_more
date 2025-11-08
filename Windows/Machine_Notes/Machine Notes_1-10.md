# Example Machine Notes

Below are summarized notes for each machine, highlighting key steps, credentials found, tools used, and the privilege escalation that led to owning the system:

## Jerry (HTB)

- **Machine:** Jerry
- **Initial Access:** Default Tomcat Manager (`tomcat:s3cret`) -> WAR upload -> Reverse shell.
- **Credentials:** `tomcat:s3cret` (default).
- **Privilege Escalation:** Not required (Tomcat ran as SYSTEM).
- **Key Tools/Techniques:** `msfvenom` (WAR payload), Tomcat Manager GUI, netcat, Metasploit (tomcat_mgr_upload).
- **Outcome:** SYSTEM shell.

## Netmon (HTB)

- **Machine:** Netmon
- **Initial Access:** Anonymous FTP (read-only) -> `user.txt` found. PRTG config backup (`PRTG Configuration.old.bak`) -> `prtgadmin:PrTg@dmin2018`.
- **Credentials:** `prtgadmin:PrTg@dmin2018` (found), `prtgadmin:PrTg@dmin2019` (guessed).
- **Privilege Escalation:** PRTG authenticated RCE (CVE-2018-9276) via Notifications settings -> SYSTEM shell.
- **Key Tools/Techniques:** FTP, manual web exploitation (PRTG), Impacket (`psexec`), netcat.
- **Outcome:** SYSTEM shell (after initial user flag via FTP).

## ServMon (HTB)

- **Machine:** ServMon
- **Initial Access:** Anonymous FTP hint -> NVMS 1000 directory traversal (CVE-2019-20085) -> `Users.zip` -> `nadine`'s credentials. SSH login as `nadine`.
- **Credentials:** `nadine`'s password (from `Users.zip`), NSClient++ admin password (in `nsclient.ini`).
- **Privilege Escalation:** NSClient++ external script execution (via web GUI or `nscp` command) -> SYSTEM shell.
- **Key Tools/Techniques:** `curl`/Burp (directory traversal), SSH, port forwarding (SSH tunnel/plink), NSClient++ web GUI/`nscp`, netcat/PowerShell (reverse shell).
- **Outcome:** SYSTEM shell (after initial user shell as `nadine`).

## Chatterbox (HTB)

- **Machine:** Chatterbox
- **Initial Access:** AChat buffer overflow (CVE-2015-1578) -> Shell as `alfred`.
- **Credentials:** None needed for initial exploit.
- **Privilege Escalation:** Not explicitly needed. `alfred` had read access to Administrator's desktop (root flag).
- **Key Tools/Techniques:** Python exploit/Metasploit (AChat overflow).
- **Outcome:** Effectively "root" access due to file permissions (as user `alfred`).

## Jeeves (HTB)

- **Machine:** Jeeves
- **Initial Access:** Unauthenticated Jenkins (port 8080) -> Script Console -> PowerShell reverse shell (as Jenkins service user).
- **Credentials:** Encrypted KeePass DB (`.kdbx`) -> cracked master password (hashcat) -> Administrator NTLM hash (inside KeePass).
- **Privilege Escalation:** Pass-the-Hash (Impacket `psexec.py`) with Administrator NTLM hash -> Administrator shell.
- **Key Tools/Techniques:** Jenkins Script Console, `keepass2john`, hashcat, `kpcli`, Impacket (`psexec.py`).
- **Outcome:** Administrator shell.

## Sniper (HTB)

- **Machine:** Sniper
- **Initial Access:** LFI in web app + IIS log poisoning -> Low-priv web shell.
- **User Escalation:** Found web config creds (`admin:Welcome1`?) -> Reused for Windows user `chris` (via WinRM/SMB/PowerShell Remoting).
- **Privilege Escalation:** As `chris`, created malicious `.chm` file (Nishang/msfvenom) -> Admin opened it -> Administrator reverse shell.
- **Key Tools/Techniques:** Burp/custom script (LFI), IIS log poisoning, `runas`/WinRM, Nishang (`Out-CHM`)/msfvenom, netcat.
- **Outcome:** Administrator shell (after initial web shell and user `chris` shell).

## Querier (HTB)

- **Machine:** Querier
- **Initial Access:** SMB share -> Excel (`Financial_Report.xlsm`) -> Hardcoded SQL credentials. MSSQL access.
- **Lateral Movement:** MSSQL `xp_dirtree`/`OPENROWSET` -> NTLM capture (Responder) -> Cracked hash (hashcat).
- **Privilege Escalation:** Higher-privilege user (from cracked hash) -> PowerUp -> GPP file (`Groups.xml`) -> Decrypted `cpassword` (Administrator's password) -> Administrator login.
- **Key Tools/Techniques:** OleTools/Excel, `mssqlclient.py` (Impacket), Responder, hashcat, PowerUp, `gppdecrypt`.
- **Outcome:** Administrator shell.

## Giddy (HTB)

- **Machine:** Giddy
- **Initial Access:** SQL Injection -> OOB NTLM hash leak -> Cracked hash -> PowerShell Web Access/WinRM as a user.
- **Credentials:** Cracked Net-NTLMv2 hash.
- **Privilege Escalation:** UniFi Video service unquoted path (CVE-2016-6914) -> Malicious `taskkill.exe` in `C:\ProgramData\unifi-video\` -> SYSTEM shell on service restart.
- **Key Tools/Techniques:** SQLmap/manual SQLi, Responder/Metasploit (SMB capture), hashcat, PowerShell Web Access/Evil-WinRM, `msfvenom`/`msvc` (malicious `taskkill.exe`), `sc stop`/`net stop`.
- **Outcome:** SYSTEM shell (after initial user shell via PSWA/WinRM).

## Bounty (HTB)

- **Machine:** Bounty
- **Initial Access:** File upload vulnerability -> ASP/ASPX web shell (IIS APPPOOL user).
- **Privilege Escalation:**
    - **Method 1:** SeImpersonatePrivilege -> Potato exploit (LonelyPotato) -> SYSTEM shell.
    - **Method 2:** Kernel exploit (MS10-092 Task Scheduler ALPC) -> Administrator shell.
- **Key Tools/Techniques:** `certutil`/`bitsadmin` (upload), ASPX shell, JuicyPotato/LonelyPotato, Metasploit (Task Scheduler exploit), precompiled kernel exploit.
- **Outcome:** SYSTEM/Administrator shell.