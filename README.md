# OSCP Cheat Sheet

## Enumeration/Scanning

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


### HTTP/HTTPS (80/443)
`nikto -h [ip]`

`dirbuster`

`robots.txt`


#### Wordpress
`nmap -p 80,443 [ip] --script=wordpress*`


### SMTP (25)
`nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 [ip]`

`telnet [ip] 25`


### Pop3 (110)
`telnet [ip] 110`

`USER [username]`

`PASS [password]`

`LIST`

`RETR`

`QUIT`


### RPCBind (111)
`rpcinfo -p [ip]


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
