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


### SMB/Samba (139, 455)
`nmap -p 139,445 [ip] --script=smb-enum*`

`nmap -p 139,445 [ip] --script=smb-os-discovery`

`nmap -p 139,445 [ip] --script=smb-vuln*`

`enum4linux -a [-u username] [-p password] [ip]`

`smbmap [-u username] [-p password] [ip]`

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
