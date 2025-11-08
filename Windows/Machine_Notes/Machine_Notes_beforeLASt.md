# Example_Machine_Notes.md

## DVR4 (Offsec PG Practice – _Windows_)

- **Initial Access:** Discovered an **Argus Surveillance DVR 4.0** web interface. Exploited a known directory traversal vulnerability (CVE-2018-15745) by requesting sensitive files via `..%2F` in the URL​[nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-15745#:~:text=Argus%20Surveillance%20DVR%204,CGI%20RESULTPAGE%20parameter). This allowed downloading the configuration file (`DVRParams.ini`), from which the credentials for a Windows user were obtained (the DVR software stored an encrypted password that was easily decoded using a known weak encryption scheme​[exploit-db.com](https://www.exploit-db.com/exploits/50130#:~:text=%23%20%20EDB)). Using these credentials, the attacker logged into the machine (e.g., via RDP or WinRM) as a standard user.
    
- **Privilege Escalation:** The Argus DVR software installed a service (`DVRWatchDog`) running with SYSTEM privileges. The attacker discovered an **unquoted service path / DLL load vulnerability** in this service. By placing a malicious DLL named `gsm_codec.dll` into the installation directory, the next service restart caused the service to execute the attacker’s code as SYSTEM​[exploit-db.com](https://www.exploit-db.com/exploits/45312#:~:text=,Affected%20Component%3A%20DVRWatchdog.exe). This yielded a SYSTEM shell, and the attacker achieved full control of the machine (administrative/root access).
    

---

## Monster (Offsec PG Practice – _Windows_)

- **Initial Access:** Enumerated a web application (a blog running **Monstra CMS**). The site hinted at a Monster’s Inc. theme (“Wazowski”), suggesting credentials. The attacker bypassed a login attempt limit by resetting a client-side cookie (`login_attempts`), allowing unlimited guesses​[medium.com](https://medium.com/@vivek-kumar/offensive-security-proving-grounds-walk-through-monster-59a4a4283449#:~:text=Running%20the%20default%20nmap%20Scripts). Using this trick, they logged into the Monstra CMS as admin (credentials `admin:wazowski`). With admin access, they generated a backup of the site through the CMS, which revealed a hashed password for user _Mike_. After extracting the backup, the attacker cracked Mike’s password hash (salt was a default value in the CMS config) to get `Mike14`​[medium.com](https://medium.com/@vivek-kumar/offensive-security-proving-grounds-walk-through-monster-59a4a4283449#:~:text=Provinggrounds). Armed with Mike’s credentials, they logged in via RDP as user Mike.
    
- **Privilege Escalation:** As user Mike, standard Windows enumeration did not reveal the usual quick wins (SeImpersonate was present but not directly exploitable)​[medium.com](https://medium.com/@vivek-kumar/offensive-security-proving-grounds-walk-through-monster-59a4a4283449#:~:text=Offensive%20Security%20Proving%20Grounds%20Walk,for%20SeImpersonatePrivilege%20as%20the%20golden%E2%80%A6). After further analysis, the attacker identified a **custom service** running on the machine that was misconfigured. By modifying this service (either via an unquoted path, weak file permissions, or exploitable binary), the attacker was able to execute code as **Administrator**. This step “scared” the machine (in line with the box’s theme) into giving up SYSTEM privileges. With Administrator access, the attacker obtained the flags and full control.
    

---

## Fish (Offsec PG Practice – _Windows_)

- **Initial Access:** Detected an **Oracle GlassFish 4.1** server on the target. Used an _authenticated directory traversal_ exploit (CVE-2017-1000028) to retrieve the GlassFish administrator credentials​[medium.com](https://medium.com/@vivek-kumar/offenisve-security-proving-grounds-walk-through-fish-fccc07ec3b0f#:~:text=There%20are%20four%20web%20application,db.com%2Fexploits%2F39441). Specifically, by sending a crafted HTTP request to the vulnerable endpoint, the attacker downloaded the `admin-keyfile`, then cracked it to reveal the admin password. With valid credentials, they accessed the GlassFish Admin Console on port 4848. There, the attacker deployed a malicious `.war` webshell through the console (leveraging the deployment feature) and obtained a reverse shell as the GlassFish service account (likely **NetworkService**).
    
- **Privilege Escalation:** Noticed another service on the machine: **SynaMan** (enterprise file sharing software) running on port 6060. Through enumeration, the attacker found that SynaMan’s installation directory had weak permissions (CVE-2022-26250)​[nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2022-26250#:~:text=Synaman%20v5,authenticated%20attackers%20to%20escalate%20privileges). The GlassFish service account had write access to SynaMan’s program files. The attacker replaced the SynaMan executable with a malicious payload. When the SynaMan service was restarted (or triggered to restart), it ran the attacker’s payload as **LocalSystem**, granting a SYSTEM shell. This provided administrative access (root on the Windows machine).
    

---

## Steel Mountain (TryHackMe)

- **Initial Access:** Found an HTTP File Server (**Rejetto HFS 2.3**) running, which is known to be vulnerable to remote code execution (CVE-2014-6287). The attacker used a public exploit for HFS to execute commands on the target​[olivierkonate.medium.com](https://olivierkonate.medium.com/steel-mountain-tryhackme-5d0c95643e4#:~:text=References), obtaining a reverse shell as a low-privileged Windows user (likely running under the HFS process). The box theme and enumeration suggested a user “Nathan” was present; the initial shell confirmed a user-level access on the system.
    
- **Privilege Escalation:** Enumerating the file system revealed an `C:\Unattend\Unattend.xml` file – a leftover from Windows automated installation. This file contained plaintext credentials for the Administrator account (username Administrator with password **TeamAlpha**)​[olivierkonate.medium.com](https://olivierkonate.medium.com/steel-mountain-tryhackme-5d0c95643e4#:~:text=2%2F%20Unquoted%20Service%20Path). Using these credentials, the attacker either logged in via RDP/WinRM or used `runas` to spawn a new shell as **Administrator**. With admin rights, the attacker had full SYSTEM access (the Administrator shell could read the root flag and perform any action on the machine).
    

---

## Year of the Owl (TryHackMe)

- **Initial Access:** The scenario was themed around the Labyrinth movie. The attacker scanned for open services and eventually tried a **WinRM login** with a likely username (e.g., `Jareth`). Based on hints, they guessed a weak password (possibly the name of a character like “**GoblinKing**” or “Sarah”) and successfully logged in as Jareth with a standard user shell. (No exploits or CVEs were needed for initial access — it was gained by **password guessing leveraging the theme**.)
    
- **Privilege Escalation:** Once on the box, the attacker discovered that the user Jareth’s **Recycle Bin contained two critical files**: backups of the `SAM` and `SYSTEM` registry hives (likely an Administrator had saved them and deleted them). By retrieving these files from the Recycle Bin, the attacker extracted password hashes, including the Administrator’s hash, using a tool like _secretsdump_. The Administrator’s NTLM hash was then cracked offline (or used in a pass-the-hash attack)​[muirlandoracle.co.uk](https://muirlandoracle.co.uk/2020/09/17/year-of-the-owl-write-up/#:~:text=Image%3A%20Jareth%27s%20recycling%20bin%20contains,hivesContents%20of%20Jareth%E2%80%99s%20Recycling%20Bin), revealing the admin password. The attacker then logged in as **Administrator** and owned the machine, obtaining the root flag.
    

---

## Retro (TryHackMe)

- **Initial Access:** Identified a website on the target hosting a retro-themed blog (WordPress). Through enumeration, the attacker discovered credentials for a user **Wade** (possibly from the WordPress database or an exposed config file). Using Wade’s username and password, they logged into the Windows box via Evil-WinRM, obtaining a user shell. (The machine’s name “Retro” hinted at older software; however, the foothold was ultimately gained by credential disclosure rather than a direct CVE exploit.)
    
- **Privilege Escalation:** While searching the user’s files, the attacker noticed a browser bookmark or note referencing “**CVE-2019-1388**.” This CVE is a known Windows **UAC bypass**. Following this lead, the attacker performed the exploit: they crafted a scenario to open the Windows Certificate Manager dialog as the low-privileged user, which triggered a high-integrity process without proper UAC prompt validation​[hackingarticles.in](https://www.hackingarticles.in/retro-tryhackme-walkthrough/#:~:text=found%20a%20link%20bookmarked,We%20read%20a%20couple%20of). By selecting “More Info” and then launching a new instance of a trusted installer, they obtained an elevated command prompt (Administrator context). This exploit gave them **Administrator privileges** on the machine, allowing access to the root flag.
    

---

## Alfred (TryHackMe)

- **Initial Access:** Detected a Jenkins automation server on the target (port 8080). The Jenkins instance had **no authentication** (default configuration), allowing the attacker to access the web dashboard. Using Jenkins’s Script Console, the attacker executed a PowerShell payload (Groovy script injection) to create a reverse shell. They gained a shell as the user account running Jenkins (likely a service account with limited privileges).
    
- **Privilege Escalation:** The Jenkins service account had the **SeImpersonatePrivilege** (token impersonation rights). The attacker migrated to a Meterpreter shell for convenience and used the **Incognito** module to list available tokens​[github.com](https://github.com/Slowdeb/Tryhackme/blob/main/Alfred.md#:~:text=match%20at%20L368%20SeImpersonatePrivilege%29%20enabled,privesc%20vertically%20to%20NT%20Authority). They found an impersonation token for **NT AUTHORITY\SYSTEM** (or for an active Administrator session). By impersonating that token, the attacker escalated to a SYSTEM-level shell. (Alternatively, they could have used tools like JuicyPotato since SeImpersonate was enabled, to get SYSTEM.) With **SYSTEM** access, they fully compromised the machine and obtained all flags.
    

---

## Relevant (TryHackMe)

- **Initial Access:** The attacker discovered SMB file shares on the target and signs of an outdated SMB service. They exploited **EternalBlue** (CVE-2017-0143, part of MS17-010) against the SMBv1 service​[madushan-perera.medium.com](https://madushan-perera.medium.com/tryhackme-relevant-walkthrough-6e7c83def069#:~:text=CVE,machine%20by%20using%20this%20vulnerability). Using a Metasploit module (MS17-010), they achieved a **SYSTEM shell directly** via the SMB vulnerability. This gave them initial access as NT AUTHORITY\SYSTEM. _(In some cases, Relevant is solved by first gaining a limited shell through SMB and then elevating; here the exploit provided system-level access immediately.)_ The attacker then created a new low-privileged user to stabilize access.
    
- **Privilege Escalation:** With only user-level access in an alternate path scenario (assuming the exploit gave a user shell), the attacker noticed that the compromised account had **SeImpersonatePrivilege** enabled. They leveraged the **PrintSpoofer** tool to abuse this privilege, which involved interacting with the Print Spooler service to impersonate **SYSTEM**​[madushan-perera.medium.com](https://madushan-perera.medium.com/tryhackme-relevant-walkthrough-6e7c83def069#:~:text=To%20perform%20privilege%20escalation%20using,%E2%80%98SeImpersonatePrivilege%2C%E2%80%99%20we%20can%20use%20PrintSpoofer). This yielded an elevated SYSTEM shell. In either case, the attacker obtained Administrator/SYSTEM privileges and was able to read the root flag, completing the challenge.
    

---

## Blueprint (TryHackMe)

- **Initial Access:** Enumerated an HTTP service on port 8080 running **osCommerce 2.3.4** (an older e-commerce web app). The installation pages for osCommerce were left accessible. The attacker exploited an **unauthenticated RCE vulnerability in the osCommerce installer** (by modifying the installation parameters to inject PHP code). This is a known issue where failing to remove the `install.php` (or `install_4.php`) page allows code injection. Using this, the attacker uploaded a PHP webshell and obtained a reverse shell as the web server user (IIS user or Apache user, depending on the setup).
    
- **Privilege Escalation:** After getting a low-privilege shell, the attacker found that Windows **AlwaysInstallElevated** policy was enabled for all users​[hackingarticles.in](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/#:~:text=%E2%80%9CAlwaysInstallElevated%E2%80%9D%20is%20a%20setting%20in,those%20with%20restricted%20privileges%2C%20to). They generated a malicious MSI package that spawns a reverse shell and then executed it on the target using `msiexec`. Because of the AlwaysInstallElevated setting, the MSI installation ran with **Administrator privileges**, thereby giving the attacker an elevated shell. With Administrator access, they had full control and retrieved the root flag.
    

---

## HackPark (TryHackMe)

- **Initial Access:** Discovered a web application using **BlogEngine.NET**. The attacker logged into the BlogEngine CMS as admin using default credentials (`admin:admin` was not working, but they brute-forced and found `admin:1qaz2wsx` as a valid login). Once in the BlogEngine dashboard, they exploited a **path traversal vulnerability (CVE-2019-6714)** in the theme upload feature to get code execution​[exploit-db.com](https://www.exploit-db.com/exploits/46353#:~:text=URL%3A%20https%3A%2F%2Fwww.exploit,0). They uploaded a malicious theme file (an .ascx webshell) and used the traversal flaw via a crafted cookie to execute it, yielding a shell as the IIS service account (BlogEngine runs as NetworkService).
    
- **Privilege Escalation:** The web service account had the ability to impersonate tokens (a common right for network service). The attacker utilized the **JuicyPotato** exploit to abuse the SeImpersonate privilege, launching a process under **NT AUTHORITY\SYSTEM**. This provided a SYSTEM-level shell on the machine. With system access, the attacker dumped the SAM database and obtained the Administrator hash, ultimately granting full control. The root flag was then recovered from the Administrator’s desktop, completing the compromise.