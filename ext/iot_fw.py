# Copyright 2013 <Your Name Here>
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

"""
Fire wall for home IoT
"""

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
from pox.lib.revent import EventRemove
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time

import re
# Create a logger for this component
log = core.getLogger()

# more list required according to upnp specification
connection_actions = {"SetAVTransportURI":"CurrentURI"}

_flood_delay = 0

def find_xmlall(xml,tag):
  ret = []
  while True:
    i = xml.find("<"+tag+">")
    if i == -1:
      return ret
    i += len(tag)+2
    xml = xml[i:]
    i = xml.find("</"+tag+">")
    ret += [xml[:i]]
    xml = xml[i:]

class UpnpDevice (object):
  def __init__ (self, ip, port, path):
    self.ip = ip
    self.port = port
    self.path = path
    self.name = ""
    self.service_path = {} #key is service name, value is service URL
    self.allow_list = {} #key is service name, value is allowed ip list
  
  def add_service(self, service, path):
    if not self.allow_list.has_key(service):
      log.debug("[%s] service %s added"%(self.name,service))
      self.allow_list[service] = []
      self.service_path[service] = path

  def add_allow(self, service, ip):
    if self.allow_list.has_key(service):
      if ip not in self.allow_list[service]:
        self.allow_list[service] += [ip]
  
  def is_allowed(self, service, ip):
    if self.allow_list.has_key(service):
      if ip in self.allow_list[service]:
        return True
    return False

class UpnpDevices (object):
  def __init__(self):
    self.devices = []

  def add(self,ip, port,path):
    if not self.find(ip,port):
      self.devices += [UpnpDevice(ip,port,path)]

  def find(self,ip,port):
    for device in self.devices:
      if device.ip == ip and device.port == port: 
        return device
    return None

class LearningSwitch (object):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}
    self.devices = UpnpDevices()
    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  
  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed
    def ssdp(event):
      packet = event.parsed
      #for ssdp packet
      ip_p = packet.find("ipv4")
      if not (ip_p and ip_p.dstip == IPAddr("239.255.255.250")): # SSDP
        return
      dev_ip = ip_p.srcip
      udp_p = packet.find("udp")
      if not udp_p:
        return
      data = udp_p.payload
      #log.debug("SSDP : \n"+data)
      port = 0
      path = ""
      for line in data.split("\r\n"):
        if line.lower().find("location")>=0:
          m=re.search("https?:\/\/([A-Za-z0-9\.-]{3,}):?(\d+)?(\/?.*)",line)
          if len(m.groups()) >= 2:
            port = int(m.group(2))
          else:
            port = 80 #default
          if len(m.groups()) == 3:
            path = m.group(3)
      if port > 0: #valid ssdp found
        if not self.devices.find(dev_ip,port):
          log.info("upnp device found:%s:%s"%(dev_ip,port))
        self.devices.add(dev_ip, port, path)

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

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
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

    ## handle_packetIn ##
    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      ssdp(event)
      flood() # 3a
    else:
      no_flow = False
      ip_p = packet.find("ipv4")
      tcp_p = packet.find("tcp")
      ### find service list from description
      if ip_p and tcp_p:
        dev = self.devices.find(ip_p.srcip, tcp_p.srcport) #from device
        if dev:
          data = tcp_p.payload
          if data:
            name = find_xmlall(data,"friendlyName")
            if len(name)>0:
              dev.name = name[0]
          if data and "serviceList" in data: #if description packet
            services = find_xmlall(data,"serviceId")
            if len(services)>0:
              for service in services:
                sid = service 
                #spath = find_xmlall(service,"controlURL")[0]
                dev.add_service(sid,"") #save service list
          else:
            no_flow=True

      ### check allow list
      if ip_p and tcp_p:
        if ip_p.srcip.in_network("192.168.0.0/24") and ip_p.dstip.in_network("192.168.0.0/24"):
          #local area network, only upnp
          dev = self.devices.find(ip_p.dstip, tcp_p.dstport) #to device 
          if dev:
            data = tcp_p.payload
            if data and "HTTP/1." in data: #if HTTP request packet
              lines = data.split("\r\n")
              log.debug("[%s] %s request from %s"%(dev.name, lines[0],ip_p.srcip))
              for line in lines:
                #SOAPACTION: "urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"
                if "SOAPACTION:" in line:
                  log.debug("%s"%(line))
                  m = re.search("(urn:.*#)(.*)",line)
                  service = m.group(1)
                  action = m.group(2)
                  log.debug(service)
                  
                  if dev.is_allowed(service,ip_p.srcip):
                    #allowed
                    #forward and setup policy
                    log.debug("=> access allowed")
                    """
                    if action in connection_actions.keys():
                      uri_tag = connection_actions[action]
                      uri = find_xmlall(data,uri_tag)[0]
                      m=re.search("https?:\/\/([A-Za-z0-9\.-]{3,}):?(\d+)?(\/?.*)",uri)
                      ip = m.group(1)
                      port = int(m.group(2))
                      #add rule for connection
                      log.debug("rule setup for %s"%(uri))
                      msg= of.ofp_flow_mod()
                      msg.match.dl_src = packet.src
                      msg.match.dl_dst = packet.dst
                      msg.match.nw_proto = 6
                      msg.match.nw_src = ip_p.srcip
                      msg.match.nw_dst = ip_p.dstip
                      msg.match.tp_src = port
                      msg.match.tp_dst = None
                      msg.idle_timeout = 10
                      msg.hard_timeout = OFP_FLOW_PERMANENT #for streaming
                      msg.actions.append(of.ofp_action_output(port = self.macToPort[packet.dst]))
                      self.connection.send(msg)
                      
                      msg= of.ofp_flow_mod()
                      msg.match.dl_src = packet.dst
                      msg.match.dl_dst = packet.src
                      msg.match.nw_proto = 6
                      msg.match.nw_src = ip_p.dstip
                      msg.match.nw_dst = ip_p.srcip
                      msg.match.tp_src = None
                      msg.match.tp_dst = port
                      msg.idle_timeout = 10
                      msg.hard_timeout = OFP_FLOW_PERMANENT #for streaming
                      msg.actions.append(of.ofp_action_output(port = self.macToPort[packet.src]))
                      self.connection.send(msg)
                    """
                  else:
                    log.debug("=> access dropped")
                    #denied
                    drop(10)
                    return
            else: # not HTTP, maybe handshaking or else
              no_flow = True
              #forward but do not setup policy
          else:
            dev = self.devices.find(ip_p.srcip, tcp_p.srcport) #from device 
            if not dev:
              log.debug("%s %d to %s %d access dropped"%(ip_p.srcip,tcp_p.srcport,ip_p.dstip,tcp_p.dstport))
              drop(10)
              return
      
      ### l2 learning switch ###
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
        #log.debug("installing flow for %s.%i -> %s.%i" %
        #          (packet.src, event.port, packet.dst, port))
        if not no_flow: 
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet, event.port)
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = event.ofp # 6a
          self.connection.send(msg)
        else:
          msg = of.ofp_packet_out()
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = event.ofp
          self.connection.send(msg)



class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  def set_length(event = None):
    if not core.hasComponent('openflow'):
      return
    core.openflow.miss_send_len = 0x7fff
    log.info("Requesting full packet payloads")
    return EventRemove
  if set_length() is None:
    core.addListenerByName("ComponentRegistered",set_length)

  core.registerNew(l2_learning, str_to_bool(transparent))

