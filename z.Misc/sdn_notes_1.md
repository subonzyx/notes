```
***************************************************************************************************************
MOST OF THESE NOTES WERE COPIED DIRECTLY FROM THE INTERNET/GUIDES/TUTORIALS/RESEARCH... FOR REFERENCE PURPOSES
***************************************************************************************************************

The Event System: pox.lib.revent

Event Handling in POX fits into the publish/subscribe paradigm.

- Certain objects publish events (in revent lingo, this is “raising” an event; also sometimes called “firing” or “dispatching” an event).
- One can then subscribe to specific events on these objects (in revent lingo, this is “listening to”; sometimes also “handling” or “sinking”).

What we mean by this is that when the event occurs, we’d like a particular piece of code to be called (an “event handler” or sometimes an “event listener”).

----

* Handling Events

So perhaps your program has an object of class Chef called chef. You know it raises a couple events. Maybe you’re interested in when your delicious spam is ready, so you’d like to listen to the SpamFinished event.

* Event Handlers

First off, let’s see exactly what an event listener looks like. For one thing: it’s a function (or a method). They almost always just take a single argument – the event object itself (though this isn’t always the case).

Assuming SpamFinished is a typical event, it might have a handler like:

def spam_ready (event):
  print "Spam is ready!  Smells delicious!"

----

* Listening To an Event

Now we need to actually set our spam_ready function to be a listener for the SpamFinished event:

chef.addListener(SpamFinished, spam_ready)

Sometimes you may not have the event class (e.g., SpamFinished) in scope. You can import it if you want, but you can also use the addListenerByName() method instead:

chef.addListenerByName("SpamFinished", spam_ready)

----

* Automatically Setting Listeners

Often, your event listener is a method on a class. Also, you often are interested in listening to multiple events from the same source object.  revent provides a shortcut for this situation: addListeners().

Assuming SpamFinished and SpamStarted are typical events, they might have handlers like:

class HungryPerson (object):
  """ Models a person that loves to eat spam """

  def __init__ (self):
    chef.addListeners(self)

  def _handle_SpamStarted (self, event):
    print "I can't wait to eat!"

  def _handle_SpamFinished (self, event):
    print "Spam is ready!  Smells delicious!"

In this case, assuming SpamFinished and SpamStarted are typical events, when you call chef.addListeners(self), it looks through the events of 'chef', and if it sees methods on itself with names like _handle_SpamStarted() and _handle_SpamFinished(), it sets those methods as listeners.

*************************************************************************************************
When you call foo.addListeners(bar), it looks through the events of 'foo', and if it sees a method on 'bar' with a name like _handle_*EventName*, it sets that method as a listener.
*************************************************************************************************

----

Communicating with Datapaths (Switches)

Switches connect to POX, and then you obviously want to communicate with those switches from POX. This communication might go either from the controller to a switch, or from a switch to the controller.

- When communication is from the controller to the switch, this is performed by controller code which sends an OpenFlow message to a particular switch.

- When messages are coming from the switch, they show up in POX as events for which you can write event handlers – generally there’s an event type corresponding to each message type that a switch might send.

While the messages themselves are described in the OpenFlow specification and the events are described in following subsections, this subsection focuses simply on how exactly you send those messages and how you set up those event handlers.

There are essentially two ways you can communicate with a datapath in POX: via a Connection object for that particular datapath or via an OpenFlow Nexus which is managing that datapath.

There is one Connection object for each datapath connected to POX, and there is typically one OpenFlow Nexus that manages all connections. In the normal configuration, there is a single OpenFlow nexus which is available as core.openflow. There is a lot of overlap between Connections and the Nexus. Either one can be used to send a message to a switch, and most events are raised on both. Sometimes it’s more convenient to use one or the other. If your application is interested in events from all switches, it may make sense to listen to the Nexus, which raises events for all switches. If you’re interested only in a single switch, it may make sense to listen to the specific Connection.

----

Connection Objects

Every time a switch connects to POX, there is also an associated Connection object. If your code has a reference to that Connection object, you can use its send() method to send messages to the datapath.

Connection objects, along with being able to send commands to switches and being sources of events from switches, have a number of other useful attributes.

In addition to its attributes and the send() method, Connection objects raise events corresponding to particular datapaths, for example when a datapath disconnects or sends a notification (for more on events in general, see the section “The Event System”). You can create handlers for events on a particular datapath by registering event listeners on the associated Connection.

----

Getting a Reference to a Connection Object

If you wish to use any of the above-mentioned attributes of a Connection object, you – of course – need a reference to the Connection object associated with the datapath you’re interested in. There are three major ways to get such a reference to a Connection object:

# In this note, only care about the first one
  1. You can listen to ConnectionUp events on the nexus – these pass the new Connection object along
  2. ...
  3. ...

As an example of the first, you may have code in your own component class which tracks connections and stores references to them itself. It does this by listening to the ConnectionUp event on the OpenFlow nexus. This event includes a reference to the new connection, which is added to its own set of connections. The following code demonstrates this (note that a more complete implementation would also want to use the ConnectionDown event to remove Connections from the set!).

class MyComponent (object):
    def __init__ (self):
        self.connections = set()
        core.openflow.addListeners(self)

    def _handle_ConnectionUp (self, event):
        self.connections.add(event.connection)

----

OpenFlow Events: Responding to Switches

Most OpenFlow related events are raised in direct response to a message received from a switch.

----

OpenFlow Events | ConnectionUp

Unlike most other OpenFlow events, this message is not raised in response to reception of a specific OpenFlow message from a switch – it’s simply fired in response to the establishment of a new control channel with a switch.

This event can be handled as shown below:

  def _handle_ConnectionUp (self, event):
    print "Switch %s has come up." % event.dpid

----

OpenFlow Events | PacketIn

This event is fired when the controller receives an OpenFlow packet-in message (ofp_packet_in / OFPT_PACKET_IN) from a switch, which indicates that a packet arriving at a switch port has either failed to match all entries in the table, or the matching entry included an action specifying to send the packet to the controller.

In addition to the usual OpenFlow event attributes:

    port (int) - number of port the packet came in on
    data (bytes) - raw packet data
### parsed (packet subclasses) - pox.lib.packet’s parsed version
    ofp (ofp_packet_in) - OpenFlow message which caused this event

Constructing Packets from Scratch and Reading Packets from the Wire

If you’re working with PacketIn objects, this is done for you automatically – the event’s .parsed property will contain the packet objects. 

This event can be handled as shown below:

  def _handle_PacketIn (self, event):
    ...
    packet = event.parsed
    ...
    def flood (message = None):
      ...

    def drop (duration = None):
      ...

----

Defining a match from an existing packet

There is a simple way to create an exact match based on an existing packet object (that is, an ethernet object from pox.lib.packet) or from an existing ofp_packet_in. This is done using the factory method ofp_match.from_packet().

my_match = ofp_match.from_packet(packet, in_port)

The packet parameter is a parsed packet or ofp_packet_in from which to create the match. As the input port is not actually in a packet header, the resulting match will have the input port wildcarded by default when this method is called with a packet. You can, of course, set the in_port field later yourself, but as a shortcut, you can simply pass it in to from_packet(). When using from_packet() with an ofp_packet_in, the in_port is taken from there by default.

----

Lab 3: Simple Firewall using OpenFlow
https://cmpe150-winter17-01.courses.soe.ucsc.edu/system/files/attachments/Lab3SimpleFirewallusingOpenFlow.pdf

- If an ofp_packet_in does not match any of the flow entries and the flow table does not have a “table-miss” flow entry, the packet will be dropped.
- If the packet matches the “table-miss” flow entry, it will be forwarded to the controller.
- If there is a match-entry for the packet, the switch will execute the action stored in the instruction field of the corresponding flow table.

----

**************

OpenFlow Messages are how OpenFlow switches communicate with controllers.

OpenFlow Messages | ofp_packet_in

When the controller receives an OpenFlow packet-in message (ofp_packet_in) from a switch, it will raise the PacketIn event which indicates that a packet arriving at a switch port has either failed to match all entries in the table, or the matching entry included an action specifying to send the packet to the controller.

Most OpenFlow related events are raised in direct response to a message received from a switch.

In this case:
- OpenFlow event:	PacketIn event
- OpenFlow message:	OpenFlow packet-in message (ofp_packet_in)

- If an ofp_packet_in does not match any of the flow entries and the flow table does not have a “table-miss” flow entry, the packet will be dropped.
- If an ofp_packet_in matches the “table-miss” flow entry, the packet will be forwarded to the controller.
- If there is a match-entry for the packet, the switch will execute the action stored in the instruction field of the corresponding flow table.

Therefore, 'packet_in' is the ofp_packet_in object the switch had sent to the controller due to a table-miss.

Table-miss flow entry

The Table-miss flow entry is the last in the table, has a priority of 0 and a match of anything. It’s like a catch-all, and the actions to be taken depend on how you configure it. You can forward the packet to the controller over the OpenFlow Channel, or you could drop the packet, or continue with the next flow table.

https://overlaid.net/2017/02/15/openflow-basic-concepts-and-theory/

**************

Lots of applications in POX interact with packets (e.g., you might want to construct packets and send them out of a switch, or you may receive them from a switch via an ofp_packet_in OpenFlow message). 

<><><><><><><>

PacketIn event is fired when the controller receives an OpenFlow packet-in message (ofp_packet_in / OFPT_PACKET_IN) from a switch, which indicates that a packet arriving at a switch port has either failed to match all entries in the table, or the matching entry included an action specifying to send the packet to the controller.

In addition to the usual OpenFlow event attributes, PacketIn event has:
    port (int) - number of port the packet came in on
    data (bytes) - raw packet data
    parsed (packet subclasses) - pox.lib.packet’s parsed version
*** ofp (ofp_packet_in) - OpenFlow message which caused this event

<><><><><><><>

OpenFlow Messages are how OpenFlow switches communicate with controllers.

OpenFlow Messages | ofp_packet_out - Sending packets from the switch

The main purpose of this message is to instruct a switch to send a packet (or enqueue it). However it can also be useful as a way to instruct a switch to discard a buffered packet (by simply not specifying any actions).

buffer_id	...
in_port		...
actions		...
data		The data to be sent (or None if sending an existing buffer via its buffer_id).
		If you specify an 'ofp_packet_in' for this => 'in_port', 'buffer_id', and 'data' will all be set correctly – this is the easiest 			way to resend a packet.

NOTE: If you receive an ofp_packet_in and wish to resend it, you can simply use it as the data attribute.

https://github.com/noxrepo/pox/blob/eel/pox/misc/of_tutorial.py


 def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.

    packet_in = event.ofp # The actual ofp_packet_in message.


 def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the controller due to a table-miss.
    """

    # "packet_in" is the ofp_packet_in object the switch had sent to the controller due to a table-miss.
    # If you receive an ofp_packet_in and wish to resend it, you can simply use it as the data attribute.
    msg = of.ofp_packet_out()
    msg.data = packet_in  # This line <=> ofp_packet_out.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

<><><><><><><>

Defining a match from an existing packet

There is a simple way to create an exact match based on an existing packet object (that is, an ethernet object from pox.lib.packet) or from an existing ofp_packet_in. This is done using the factory method ofp_match.from_packet().

	my_match = ofp_match.from_packet(packet, in_port)

The packet parameter is a parsed packet or ofp_packet_in from which to create the match.

**************

Match Structure

OpenFlow defines a match structure 'ofp_match' which enables you to define a set of headers for packets to match against.

ofp_match Attributes:

Attribute 	Meaning
-----------|----------------------------------------------------------
in_port 	Switch port number the packet arrived on
dl_src 		Ethernet source address
dl_dst 		Ethernet destination address
...
...
dl_type 	Ethertype / length (e.g. 0x0800 = IPv4)
nw_proto 	IP protocol (e.g., 6 = TCP) or lower 8 bits of ARP opcode
nw_src 	IP source address
nw_dst 	IP destination address
tp_src 	TCP/UDP source port
tp_dst 	TCP/UDP destination port

Attributes may be specified either on a match object or during its initialization. That is, the following are equivalent:

	my_match = of.ofp_match(in_port = 5, dl_dst = EthAddr("01:02:03:04:05:06"))
	# OR...
	my_match = of.ofp_match()
	my_match.in_port = 5
	my_match.dl_dst = EthAddr("01:02:03:04:05:06")

ofp_match Methods

Method 							Description
-----------------------------------------------------|---------------------------------------------------------------------------
from_packet(packet, in_port=None, spec_frags=False) 	Class factory. See “Defining a match from an existing packet” below.
clone() 						Returns a copy of this ofp_match.
...
...
show() 	Returns a large string representation.
get_nw_src() 						Returns the IP source address and the number of matched bits as a tuple.
set_nw_src(IP and bits) 				Sets the IP source address and the number of bits to match.
get_nw_dst()					 	Same as get_nw_src() but for destination address.
set_nw_dst(IP and bits) 				Same as set_nw_src() but for destination address.

Defining a match from an existing packet

There is a simple way to create an exact match based on an existing packet object - that is either:
- An ethernet object from pox.lib.packet
OR
- An existing ofp_packet_in. 

This is done using the factory method ofp_match.from_packet().

    my_match = ofp_match.from_packet(packet, in_port)

The packet parameter is either:
- A parsed packet
OR
- ofp_packet_in from which to create the match

As the input port is not actually in a packet header, the resulting match will have the input port wildcarded by default when this method is called with a packet. You can, of course, set the in_port field later yourself, but as a shortcut, you can simply pass it in to from_packet(). When using from_packet() with an ofp_packet_in, the in_port is taken from there by default.

Example: Matching Web Traffic

As an example, the following code will create a match for traffic to web servers:

    import pox.openflow.libopenflow_01 as of # POX convention
    import pox.lib.packet as pkt # POX convention
    my_match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_proto = pkt.ipv4.TCP_PROTOCOL, tp_dst = 80)

<><><><><><><>

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PacketIn

Switch -> PacketIn -> Controller

http://flowgrammable.org/sdn/openflow/message-layer/packetin/

The PacketIn message is a way for the switch to send a captured packet to the controller. There are two reasons why this might happen; there could be an explicit action as a result of a match asking for this behavior, or from a miss in the match tables, or a ttl error.

- A PacketIn message consists of the header, followed by a buffer_id.
	The buffer_id field is a unique value used to track the buffered packet.
- The total_len field indicates the length of the captured packet.
- The in_port field indicates the port where the packet was received on.
- The reason field indicates why the packet has been captured and forwarded.
- Finally, the captured portion of the packet starts just beyond the pad.

Message Structure

Name 		Bits 	Byte Ordering 	Constraints
buffer_id 	32 	MSBF 		none
total_len 	16 	MSBF 		none
in_port 	16 	MSBF 		none
reason 		8 	- 		See Table
pad 		8 	- 		none
data 		48 	MSBF 		none

------

PacketOut

Controller -> PacketOut -> Switch

http://flowgrammable.org/sdn/openflow/message-layer/packetout/

The controller has the ability to inject packets into the data plane of a particular switch. it does this with the PacketOut message, which can either carry a raw packet to inject into the switch, or indicate a local buffer on the switch containing a raw packet to release. Packets injected into the data plane of a switch using this method are not treated the same as packets that arrive on standard ports. The packet jumps to the action set application stage in the standard packet processing pipeline. If the action set indicates table processing is necessary then the input port id is used as the arrival port of the raw packet.

OpenFlow Messages | ofp_packet_out - Sending packets from the switch

The main purpose of this message is to instruct a switch to send a packet (or enqueue it). However it can also be useful as a way to instruct a switch to discard a buffered packet (by simply not specifying any actions).

- The buffer_id field indicates the location of a raw packet to be injected into the data plane of the switch. A value of 0xffffffff indicates that the raw packet is contained within the byte array data[], otherwise the buffer_id value indicates a packet buffer local to the switch that contains the raw packet.
- The in_port field is used as the arrival port if the raw packet has to undergo standard table processing.
	*** in_port is also a switch port that the packet arrived on if resending a packet.
- Actions_len indicates the number of bytes the set of actions consume.
- The action[] is a list of actions to apply to the raw packet.
- Finally, the data[] field is a byte array containing a raw packet.

Message Structure

Name 		Bits 	Byte Ordering 	Constraints
buffer_id 	32 	MSBF 		none
in_port 	16 	MSBF 		in 0..0xff00
actions_len 	16 	MSBF 		none
actions[] 	32 	MSBF 		see action
data[] 		- 	- 		none

Example: Sending a PacketOut

In a similar manner to a flow mod, one must first define a packet out as shown here:

	msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
	msg.actions.append(of.ofp_action_output(port = outport))
	msg.buffer_id = <some buffer id, if any>
	connection.send(msg)

The 'in_port' is set to OFPP_NONE because the packet was generated at the controller and did not originate as a packet in at the datapath.

Note:
- The in_port field is used as the arrival port if the raw packet has to undergo standard table processing.
	*** in_port is also a switch port that the packet arrived on if resending a packet.

------

Action

http://flowgrammable.org/sdn/openflow/message-layer/action/

An action is a policy decision on what should happen to a packet. OpenFlow uses actions either direction in matches or in instructions; both of which are used in flow modifications.

Action Payload

Type Name 	Type Value 	Field Name 	Bits 	Byte Ordering 	Constraints
Output 		0x0000 		type 		16 	MSBF 		= 0x0000
				length 		16 	MSBF 		= 0x0008
				port 		16 	MSBF 		in 0x0000..0xffef
				max_len 	16 	MSBF 		none

OpenFlow Actions | Output

Forward packets out of a physical or virtual port. Physical ports are referenced to by their integral value, while virtual ports have symbolic names. Physical ports should have port numbers less than 0xFF00.

Structure definition:

class ofp_action_output (object):
  def __init__ (self, **kw):
    self.port = None # Purposely bad -- require specification

port (int) the output port for this packet. Value could be an actual port number or one of the following virtual ports:
   OFPP_IN_PORT - Send back out the port the packet was received on
   ...
   OFPP_FLOOD - output all openflow ports except the input port and those with flooding disabled via the OFPPC_NO_FLOOD port config bit
   OFPP_ALL -  output all openflow ports except the in port
   OFPP_CONTROLLER - Send to the controller
   OFPP_LOCAL - Output to local openflow port
   OFPP_NONE - Output to no where

------

FlowMod

Controller -> FlowMod -> Switch

http://flowgrammable.org/sdn/openflow/message-layer/flowmod/

This is one of the main messages, it allows the controller to modify the state of an OpenFlow switch; All FlowMod messages begin with the standard OpenFlow header, containing the appropriate version and type values, followed by the FlowMod structure.

- This message begins with the standard header and is followed by match, a cookie, which is an opaque field set by the controller, and command which specifies the type of flow table modification. 
- This is followed by idle_timeout, hard_timeout and priority. 
	Idle_timeout and hard_timeout represent number of seconds since packet inactivity and creation since expiration, respectively.
	Priority implies an order for matches that overlap with higher numbers representing higher priorities.
- Next in the FlowMod are buffer_id, out_port and flags.
	Buffer_id is the id of buffered packet that created a packet_in, make FlowMod and then reprocess the packet.
	Flag is set whether the flow can: send FlowRemoved, send Error if overlap, or function only if controller connectivity is lost.
- Finally, actions specifies what actions should be taken for matching packets.

Message Structure
Name 		Bits 	Byte Ordering 	Constraints
match 		32 	MSBF 		match restrictions
cookie 		64 	MSBF 		!= 0xFFFFFFFFFFFFFFFF
command 	16 	MSBF 		See below
idle_timeout 	8 	- 		none
hard_timeout 	8 	- 		none
priority 	8 	- 		none
buffer_id 	32 	MSBF 		none
out_port 	16 	MSBF 		none
flags 		16 	MSBF 		See below
action[] 	32 	MSBF 		action restrictions

    match (ofp_match) - the match structure for the rule to match on (see below).
    cookie (int) - identifier for this flow rule. (optional)
    command (int) - One of the following values:
        OFPFC_ADD - add a rule to the datapath (default)
        OFPFC_MODIFY - modify any matching rules
        OFPFC_MODIFY_STRICT - modify rules which strictly match wildcard values.
        OFPFC_DELETE - delete any matching rules
        OFPFC_DELETE_STRICT - delete rules which strictly match wildcard values.
    idle_timeout (int) - rule will expire if it is not matched in ‘idle_timeout’ seconds.
    hard_timeout (int) - rule will expire after ‘hard_timeout’ seconds. A value of OFP_FLOW_PERMANENT means it will never expire (the default)
    priority (int) - the priority at which a rule will match, higher numbers higher priority. Note: Exact matches will have highest priority.
    buffer_id (int) - A buffer on the datapath that the new flow will be applied to. Use None for none. Not meaningful for flow deletion.
    out_port (int) - This field is used to match for DELETE commands. OFPP_NONE may be used to indicate that there is no restriction.
    flags (int) - Integer bitfield in which the following flag bits may be set:
        OFPFF_SEND_FLOW_REM - Send flow removed message to the controller when rule expires
        OFPFF_CHECK_OVERLAP - Check for overlapping entries when installing. If one exists, then an error is send to controller
        OFPFF_EMERG - Consider this flow as an emergency flow and only use it when the switch controller connection is down.
    actions (list) - actions are defined below, each desired action object is then appended to this list and they are executed in order.

Example: Sending a FlowMod

To send a flow mod you must define a match structure (discussed above) and set some flow mod specific parameters as shown here:

	msg = ofp_flow_mod()
	msg.match = match
	msg.idle_timeout = idle_timeout
	msg.hard_timeout = hard_timeout
	msg.actions.append(of.ofp_action_output(port = port))
	msg.buffer_id = <some buffer id, if any>
	connection.send(msg)

Example: Installing a table entry + traffic to 192.168.100.100:80 should be sent out switch port 4

	# Traffic to 192.168.100.100:80 should be sent out switch port 4

	# One thing at a time...
	msg = of.ofp_flow_mod()
	msg.priority = 42
	msg.match.dl_type = 0x800
	msg.match.nw_dst = IPAddr("192.168.100.100")
	msg.match.tp_dst = 80
	msg.actions.append(of.ofp_action_output(port = 4))
	self.connection.send(msg)

	# OR

	# Same exact thing, but in a single line...
	self.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=4 ),
		                               priority=42,
		                               match=of.ofp_match( dl_type=0x800,
		                                                   nw_dst="192.168.101.101",
		                                                   tp_dst=80 )))

**************

IN TRADITIONAL NETWORK ARCHITECTURE
Traditionally, a network device can be separated into three different planes:

* The control plane is responsible for making the decisions as to how a specific packet is handled (for example, should it be forwarded? If so, via which port?). This is commonly done on traditional devices with static routes or via dynamic routing protocols.

* The management plane is responsible for the management of a device; an example of this would be using telnet or SSH to connect to a device that is then managed through the CLI.

* The data plane is where the bulk of the device's activity is completed; this includes the actual forwarding of data in a specific port and out a specific port based on a forwarding table or base (FIB).

------

Mininet Sample Workflow

Once a design works on Mininet, it can be deployed on hardware for real-world use, testing and measurement.
To successfully port to hardware on the first try, every Mininet-emulated component must act in the same way as its corresponding physical one.

- The virtual topology should match the physical one; virtual Ethernet pairs must be replaced by link-level Ethernet connectivity.
- Hosts emulated as processes should be replaced by hosts with their own OS image.
- In addition, each emulated OpenFlow switch should be replaced by a physical one configured to point to the controller.
- However, the controller does not need to change. When Mininet is running, the controller “sees” a physical network of switches, made possible by an interface with well-defined state semantics.

------

OpenFlow is a flow-based switch specification designed to enable
researchers to run experiments in live networks.  OpenFlow is based on a
simple Ethernet flow switch that exposes a standardized interface for
adding and removing flow entries.

An OpenFlow switch consists of three parts: 
(1) A "flow table" in which each flow entry is associated with an action telling the switch how to process the flow.
(2) A "secure channel" connecting the switch to a remote process (a controller), allowing commands and packets to be sent between the controller and the switch.
(3) An OpenFlow protocol implementation, providing an open and standard way for a controller to talk to the switch.

https://github.com/mininet/openflow
```
