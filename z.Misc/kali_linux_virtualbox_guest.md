```
# uname -r

# nano /etc/apt/sources.list

--------------------------
deb http://http.kali.org/kali kali-rolling main non-free contrib
--------------------------

# apt-get update

# apt-get install linux-image- (press Tab for more info)
# apt-get install linux-image-4.16.0-kali2-amd64 (get the latest version)

# uname -r
# reboot

# apt-get install linux-headers- (press Tab for more info)
# apt-get install linux-headers-$(uname -r) (get the latest version)

# cp /media/cdrom/VBoxLinuxAdditions.run ./
# chmod 755 VBoxLinuxAdditions.run
# ./VBoxLinuxAdditions.run

# reboot
```
