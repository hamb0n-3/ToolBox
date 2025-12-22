nmap --script "ldap* and not brute" $ip -p 389 -v -Pn -sT <IP>
ldapsearch -x -h <IP> -b "dc=X,dc=Y"
