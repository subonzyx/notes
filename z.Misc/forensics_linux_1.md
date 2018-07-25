```
$ sudo apt-get install dwarfdump
$ sudo apt-get install build-essential
$ sudo apt-get install linux-headers-`uname -r`

$ sudo zip ~/Ubuntu1704.zip ~/volatility-2.5/tools/linux/module.dwarf /boot/System.map-4.10.0-19-generic

$ cp ~/Ubuntu1704.zip ~/volatility-2.5/volatility/plugins/overlays/linux/

$ cp ~/LiME-master/src/lime-4.10.0-19-generic.ko ~

$ sudo insmod ~/lime-4.10.0-19-generic.ko "path=/mnt/alex_06022017.lime format=lime"

$ cp /mnt/alex_06022017.lime ~
```

https://dominicbunch.wordpress.com/2014/10/11/volatility-and-lime-on-ubuntu-14-04/

https://github.com/504ensicsLabs/LiME

https://infosectrek.wordpress.com/2014/02/22/step-by-step-guide-to-using-lime-the-linux-memory-extractor/

