net user /domain
net user <USER> /domain
net group /domain
net group <GROUP> /domain
Get-DomainUser -PreauthNotRequired
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}
Find-DomainUserLocation -ComputerUnconstrained -ShowAll
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation
Get-DomainGPOUserLocalGroupMapping -Identity <User/Group>
Get-DomainGPOUserLocalGroupMapping -Identity <USER> -Domain <DOMAIN> -LocalGroup RDP
Add-DomainObjectAcl -TargetIdentity matt -PrincipalIdentity will -Rights ResetPassword -Verbose
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'}

https://wadcoms.github.io/#+Exploitation

Get-NetDomain
Get-NetUser
Get-NetGroup
Get-ObjectAcl -Identity <USERNAME>
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
Get-NetComputer | select operatingsystem
Find-LocalAdminAccess
Get-NetSession -ComputerName <COMPUTER-NAME>
Get-NetUser -SPN | select samaccountname,serviceprincipalname

.\PsLoggedon.exe \\<COMPUTER-NAME>
