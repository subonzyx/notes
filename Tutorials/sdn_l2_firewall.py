# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Customerized for firewall example
#
# TO run in mininet:
# ----------------
#  First launch a mininet with a single switch and three hosts
#  This can be done using a command line or a custom topo file in Python
#  Then launch the firewall:
#    pox log.level --DEBUG l2_firewall --firewall_file=<name of filewall rules file> 
#   
#  

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.addresses import EthAddr

import time
import os

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class FirewallSwitch (object):

  def __init__ (self, connection, transparent, firewall_file):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection    = connection
    self.transparent   = transparent
    self.firewall_file = firewall_file 

    # Our table forwarding
    self.macToPort = {}

    # LID: firewall hash table and init with rules
    self.firewall = {}
    # LID: add rules to allow h1 and h2 to ping each other
    log.info("*** Firewall rules are in the file %s" % (firewall_file))

    self.AddRule2(dpid_to_str(self.connection.dpid))
    
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    log.debug("Initializing FirewallSwitch, transparent=%s",
              str(self.transparent))

  def AddRule2(self, dpidstr):
    #Read the rule from the file and add them
    f = None
    try:
        f = open(self.firewall_file)
        for src in f:
           # Need to strip off the carriage return at the end
           # and check if the string is empty
           src = src[:-1]
           if src:
           	#log.info("*** Adding rule for Switch [%s], Source MAC address is [%s]" % (dpidstr.split("-")[5],src))
           	self.firewall[(dpidstr,EthAddr(src))] = True 
           	log.info("*** Added firewall rule in Switch [%s] for Source MAC address [%s]", dpidstr.split("-")[5], EthAddr(src))
    except: 
	log.debug("*** Something is wrong with adding rules! ")
        raise RuntimeError("*** Error adding firewall rules")
    finally:
        log.info("*** Done reading filewall rules")
        f.close()
  
  # LID: check firewall rules
  def CheckRule(self, dpidstr, src = 0):
    try:
      entry = self.firewall[(dpidstr, src)]
      if entry == True:
        log.debug("Rule on MAC address [%s] found in Switch [%s]: FORWARD", src, dpidstr.split("-")[5])
      else:
        log.debug("Rule on MAC %s found in %s: DROP", src, dpidstr.split("-")[5])

      return entry
    except KeyError:
        log.debug("Rule on MAC address [%s] NOT found in Switch [%s]: DROP", src, dpidstr.split("-")[5])
        return False

  def checkRules_Xmas(self,packet):
    if packet.find('tcp') != None :
      tcp_header = packet.find('tcp')
      log.debug("Xmas scans...") 
      if tcp_header.FIN and tcp_header.PSH and tcp_header.URG:
        return False
      
  # LID: delete rule from firewall
  def DeleteRule(self, dpidstr, src = 0):
    try:
      del self.firewall[(dpidstr,src)]
      log.debug("Rule on MAC %s deleted in %s", src, dpidstr)
    except KeyError:
      log.error("Rule on MAC %s NOT found in %s", src, dpidstr)

  # LID: handle flow removed event
  """
  def _handle_FlowRemoved(self,event):
    log.info("Flow Removed on [%s]", dpid_to_str(event.dpid))
    #import pdb; pdb.set_trace()

    # Find out the reason for removal
    reason = event.ofp.reason
    if reason == of.OFPRR_IDLE_TIMEOUT:
      log.info(" Reason: idle timeout")
    elif reason == of.OFPRR_HARD_TIMEOUT:
      log.info(" Reason: hard timeout")
    else:
      log.info(" Reason unclear")

    # Find out which flow is removed
    flow_removal = event.ofp.match
    log.info(" Removed flow src: %s - dst: %s", flow_removal.nw_src, flow_removal.nw_dst)
  """
        
  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    #import pdb; set_trace()
    packet = event.parsed
    log.debug("------------------------------------------------------------------")
    log.debug("PacketIn!")
    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None:
	  log.debug(message)
        log.debug("[%i]: flooding... [%s -> %s]", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    # LID: Check if the packet from this source is allowed by firewall
    dpidstr = dpid_to_str(event.connection.dpid)

    if self.CheckRule(dpidstr,packet.src) == False:
      log.debug("Firewall to drop packet from MAC address [%s] -> MAC address [%s]"
              % (packet.src, packet.dst))
      drop()
      return

    if self.checkRules_Xmas(packet) == False:
      ip = packet.find('ipv4')
      log.debug("PSH, URG and FIN flags detected!")
      log.debug("Drop Xmas packets from [%s] -> [%s]"
              % (ip.srcip, ip.dstip))
      drop()
      return

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood("Destination is multicast") # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("Installing flow entry [%s:%i -> %s:%i]" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.flags |= of.OFPFF_SEND_FLOW_REM
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)

class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent, firewall_file):

    core.openflow.addListeners(self) # Core will register the callback function
                                     # starts with _handle_xxx
    self.transparent = transparent
    self.firewall_file = firewall_file 

  # handler for ConnectionUp event
  # also create a FirewallSwitch object instance
  # and pass the connection object

  def _handle_ConnectionUp (self, event):
    log.debug("LID Connection %s" % (event.connection))
    FirewallSwitch(event.connection, self.transparent, self.firewall_file)

#
# launch
#
def launch (transparent=False, hold_down=_flood_delay, rule = "l2_firewall_rules.csv"):
  """
  Starts an L2  switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  #import pdb; pdb.set_trace()

  # Check the firewall file exists locally and not empty
  log.info("*** Firewall file : %s", (rule))
  if os.path.isfile(rule) == False:
     #log.debug("*** Firewall file %s not found!",(rule))
     raise RuntimeError(" Firewall rules %s not found!" % (rule))
  else:
     if os.stat(rule).st_size == 0:
         #raise RuntimeError(" Firewall rules %s empty!" % (rule))
         log.info("*** Warning: empty firewall rules!")

  log.info("*** Firewall file: %s found!" % (rule))
	  
  # LID: Register l2_learning class with the core 
  core.registerNew(l2_learning, str_to_bool(transparent), rule)

