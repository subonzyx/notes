#######################################################
## Source: http://csie.nqu.edu.tw/smallko/sdn/lab9.htm
#######################################################

#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.log import  setLogLevel, info
from threading import Timer
from mininet.util import quietRun
from time import sleep
from mininet.cli import CLI

def myNet(cname='controller', cargs='-v ptcp:'):
    "Create network from scratch using Open vSwitch."
    info( "*** Creating nodes\n" )
    controller = Node( 'c0', inNamespace=False )
    s0 = Node( 's0', inNamespace=False )
    s1 = Node( 's1', inNamespace=False )
    h0 = Node( 'h0' )
    h1 = Node( 'h1' )
    h2 = Node( 'h2' )

    info( "*** Creating links..." )
    linkopts0=dict(bw=10, delay='1ms', loss=0)
    info( '\nLink h0-s0 | ' )
    TCLink( h0, s0, **linkopts0)
    info( '\nLink h1-s0 | ' )
    TCLink( h1, s0, **linkopts0)
    info( '\nLink s0-s1 | ' )
    TCLink( s0, s1, **linkopts0)
    info( '\nLink s1-h2 | ' )
    TCLink( s1, h2, **linkopts0)

    info( '\n' )
    info( "*** Configuring hosts...\n" )
    h0.setIP( '192.168.1.1/24' )
    h1.setIP( '192.168.1.2/24' )
    h2.setIP( '192.168.1.3/24' )

    info( "*** Starting network using Open vSwitch...\n" )
    s0.cmd( 'ovs-vsctl del-br s0' )
    s0.cmd( 'ovs-vsctl add-br s0' )
    s1.cmd( 'ovs-vsctl del-br s1' )
    s1.cmd( 'ovs-vsctl add-br s1' )

    controller.cmd( cname + ' ' + cargs + '&' )          
    for intf in s0.intfs.values():
        print intf
        print s0.cmd( 'ovs-vsctl add-port s0 %s' % intf )
   
    for intf in s1.intfs.values():
        print intf
        print s1.cmd( 'ovs-vsctl add-port s1 %s' % intf )
  
    # Note: controller and switch are in root namespace, and we
    # can connect via loopback interface
    info( '*** Connect to controller with tcp port...' )
    s0.cmd( 'ovs-vsctl set-controller s0 tcp:127.0.0.1:6633' )
    s1.cmd( 'ovs-vsctl set-controller s0 tcp:127.0.0.1:6633' )
 
    info( '\n' )  
    info( '*** Waiting for switch to connect to controller..' )
    while 'is_connected' not in quietRun( 'ovs-vsctl show' ):
        sleep( 1 )
        info( '.' )
    info( 'connected!\n' )

    #print s0.cmd('ovs-ofctl show dp0')

    info( "*** Running test...\n" )
    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n' )
    h0.cmdPrint( 'ping -c 2 ' + h2.IP() )
    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n' )
    h1.cmdPrint( 'ping -c 2 ' + h2.IP() )
    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n' )

    info( '*** Starting iperf Server...\n' )
    h2.cmdPrint('iperf -s -i 1 > bandwidth_result &')

    info( '*** Original link bandwidth testing...\n' )
    print "iperf: h0--s0--s1--h2"
    h0.cmdPrint('iperf -c 192.168.1.3 -t 15')
    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n' )
    print "iperf: h1--s0--s1--h2"
    h1.cmdPrint('iperf -c 192.168.1.3 -t 15')
    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n' )

    print "!!! Limiting the bandwidth for flow entry [h0] -> [h2]"
    s0.cmdPrint('ethtool -K s0-eth2 gro off')
    s0.cmdPrint('tc qdisc del dev s0-eth2 root')
    s0.cmdPrint('tc qdisc add dev s0-eth2 root handle 1: cbq avpkt 1000 bandwidth 10Mbit')
    s0.cmdPrint('tc class add dev s0-eth2 parent 1: classid 1:1 cbq rate 512kbit allot 1500 prio 5 bounded isolated')
    s0.cmdPrint('tc filter add dev s0-eth2 parent 1: protocol ip prio 16 u32 match ip src 192.168.1.1 flowid 1:1')
    s0.cmdPrint('tc qdisc add dev s0-eth2 parent 1:1 sfq perturb 10')

    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~' )
    info( '\n*** Limited link bandwidth testing...\n' )
    print "iperf: h0--s0--s1--h2"
    h0.cmdPrint('iperf -c 192.168.1.3 -t 15')
    info( '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n' )
    print "iperf: h1--s0--s1--h2" 
    h1.cmdPrint('iperf -c 192.168.1.3 -t 15')

    info( '*** Done...\n' )
    info( "*** Stopping network...\n" )
    controller.cmd( 'kill %' + cname )
    s0.cmd( 'ovs-vsctl del-br s0' )
    s0.deleteIntfs()
    s1.cmd( 'ovs-vsctl del-br s1' )
    s1.deleteIntfs()
    info( '\n' )

if __name__ == '__main__':
    global net
    setLogLevel( 'info' )
    #info( '*** Scratch network demo (kernel datapath)\n' )
    Mininet.init()
    myNet()

