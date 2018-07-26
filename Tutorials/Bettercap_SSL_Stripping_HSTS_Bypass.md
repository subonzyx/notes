
##    Bettercap - SSL Stripping + HSTS Bypass   

https://www.youtube.com/watch?v=6hgfumOYizY

Network Configuration
```
--------------------         ------------------
|                  |---------|     Attacker   |
|      Router      |         |  192.168.1.10  |
|                  |         ------------------
|                  |         ------------------
|   192.168.1.1    |---------|     Victim     |
|                  |         |  192.168.1.15  |
--------------------         ------------------
```
1. Introduction

####    SSL Stripping      

SSL stripping is a technique introduced by Moxie Marlinspike during BlackHat DC 2009. Generally speaking, this technique will replace every 'https' link in webpages the target is browsing with 'http' ones so, if a page would normally look like:
```
... <a href="https://www.facebook.com/">Login</a> ...
```
During a SSL stripping attack its HTML code will be modified as:
```
... <a href="http://www.facebook.com/">Login</a> ...
```
Being the man in the middle, this allow us to sniff and modify pages that normally we wouldn't be able to even see.

####   HSTS Bypass

SSL stripping worked quite well until 2010, when the HSTS specification was introduced. Wikipedia says that:

"HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797."

Moreover HSTS policies have been prebuilt into major browsers meaning that now, even with a SSL stripping attack running, the browser will connect to HTTPS anyway, even if the http:// schema is specified, making the attack itself useless.

For this reason, Leonardo Nve Egea presented sslstrip+ (or sslstrip2) during BlackHat Asia 2014. This tool was an improvement over the original Moxie's version, specifically created to bypass HSTS policies. Since HSTS rules most of the time are applied on a per-hostname basis, the trick is to downgrade HTTPS links to HTTP and to prepend some custom sub domain name to them. Every resulting link won't be valid for any DNS server, but since we're MITMing we can resolve these hostnames anyway.

Let's take the previous example page:
```
... <a href="https://www.facebook.com/">Login</a> ...
```
A HSTS bypass attack will change it to something like:
```
... <a href="http://wwwwww.facebook.com/">Login</a> ...
```
Notice that `https` has been downgraded to `http` and `www` replaced with `wwwwww`

When the "victim" will click on that link, no HSTS rule will be applied (since there's no rule for such subdomain we just created) and the MITM software (Bettercap in our case ^_^) will take care of the DNS resolution, allowing us to see and alter the traffic we weren't supposed to see.

References:

https://www.bettercap.org/legacy/index.html#http

2. Using Bettercap to conduct SSL Stripping + HSTS Bypass
```
# sudo bettercap -I eth0 -X --gateway 192.168.1.1 --target 192.168.1.15 --proxy --parsers POST
```
- On victim machine, use specific credentials as follows:

* For AIS Moodle website:
```
Username: AIS_Moodle_Username
Password: AIS_Moodle_Password
```
- Let's have a look at traffic sniffed from Bettercap

* For Twitter website:
```
Username: AIS_Twitter_Username
Password: AIS_Twitter_Password
```
- Let's have a look at traffic sniffed from Bettercap

* Comma separated list of available packet parsers to enable: COOKIE, CREDITCARD, DHCP, DICT, FTP, HTTPAUTH, HTTPS, IRC, MAIL, MPD, MYSQL, NNTP, NTLMSS, PGSQL, POST, REDIS, RLOGIN, SNMP, SNPP, URL, WHATSAPP...

