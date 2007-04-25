#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

# Dissector for Ethernet
class Ether<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :dst, :src, :type

def init

  @protocol = 'Ethernet'
  @fields_desc =  [ MACField('dst', '00:00:00:00:00:00'),
                    MACField('src', '00:00:00:00:00:00'),
                    XShortField('type', ETHERTYPE_IPv4) ]
end

end

# Dissector for IPv4
class IP<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :version_ihl, :tos, :len, :id, :flags_offset, :ttl,
:proto, :chksum, :src, :dst

def init
  @protocol = 'IPv4'
  @fields_desc = [ XByteField('version_ihl', 0x45),
                   XByteField('tos', 0),
                   ShortField('len', 20),
                   XShortField('id', 0),
                   ShortField('flags_offset', 0),
                   ByteField('ttl', 64),
                   ByteField('proto', IPPROTO_TCP),
                   XShortField('chksum', 0),
                   IPField('src', '127.0.0.1'),
                   IPField('dst', '127.0.0.1') ]
end

def pre_send(underlayer, payload)

  # Total length
  self.len = 20 + payload.length

  # Checksum
  self.chksum = 0
  self.chksum = Layer.checksum(self.tonet())
end

end

# Dissector for ICMP
class ICMP<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :type, :code, :chksum, :id, :seq

def init
  @protocol = 'ICMP'
  @fields_desc = [ ByteField('type', ICMPTYPE_ECHO),
                   ByteField('code', 0),
                   XShortField('chksum', 0),
                   XShortField('id', 0),
                   XShortField('seq', 0) ]
end

def pre_send(underlayer, payload)
  # Checksum
  self.chksum = 0
  self.chksum = Layer.checksum(self.tonet() + payload)
end

end

# Dissector for Raw
class Raw<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :load

def init
  @protocol = 'Raw'
  @fields_desc = [ StrField('load', '') ]
end

end

# Dissector for TCP
class TCP<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :sport, :dport, :seq, :ack, :dataofs_reserved, :flags,
:window, :chksum, :urgptr

def init
  @protocol = 'TCP'
  @fields_desc = [ ShortField('sport', 1024),
                   ShortField('dport', 80),
                   IntField('seq', 0),
                   IntField('ack', 0),
                   ByteField('dataofs_reserved', 0x50),
                   XByteField('flags', 0x2),
                   ShortField('window', 8192),
                   XShortField('chksum', 0),
                   ShortField('urgptr', 0) ]
end

def pre_send(underlayer, payload)

  # To compute the TCP checksum, the IP underlayer is needed.
  # Otherwise, the chksum field is left equal to 0.
  if underlayer.is_a?(IP)

    # Getting IP addresses from the IPFields
    ip_src = underlayer.fields_desc[8].tonet(underlayer.fields_desc[8])
    ip_dst = underlayer.fields_desc[9].tonet(underlayer.fields_desc[9])

    pseudo_header = [ip_src,
                     ip_dst,
                     underlayer.proto,
                     (self.tonet() + payload).length
                    ].pack("a4a4nn")
    
    self.chksum = 0
    self.chksum = Layer.checksum(pseudo_header + self.tonet() + payload)
  end
end

end

# Dissector for UDP
class UDP<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :sport, :dport, :len, :chksum

def init
  @protocol = 'UDP'
  @fields_desc = [ ShortField('sport', 53),
                   ShortField('dport', 53),
                   ShortField('len', 8),
                   XShortField('chksum', 0) ]
end

# Almost the same as TCP
def pre_send(underlayer, payload)

  # Total length
  self.len = 8 + payload.length
  
  # To compute the UDP checksum, the IP underlayer is needed.
  # Otherwise, the chksum field is left equal to 0.
  if underlayer.is_a?(IP)

    # Getting IP addresses from the IPFields
    ip_src = underlayer.fields_desc[8].tonet(underlayer.fields_desc[8])
    ip_dst = underlayer.fields_desc[9].tonet(underlayer.fields_desc[9])

    pseudo_header = [ip_src,
                     ip_dst,
                     underlayer.proto,
                     (self.tonet() + payload).length
                    ].pack("a4a4nn")
    
    self.chksum = 0
    self.chksum = Layer.checksum(pseudo_header + self.tonet() + payload)
  end

end

end

# Dissector for the classic BSD loopback header (NetBSD, FreeBSD and Mac OS X)
class ClassicBSDLoopback<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :header

def init
  @protocol = 'Classic BSD loopback'
  @fields_desc = [ HostOrderLongField('header', BSDLOOPBACKTYPE_IPv4) ]
end

end

# Dissector for the OpenBSD loopback header
class OpenBSDLoopback<Layer
def method_missing(method, *args) return Scruby.field(method, *args) end

attr_accessor :header

def init
  @protocol = 'OpenBSD loopback'
  @fields_desc = [ LELongField('header', BSDLOOPBACKTYPE_IPv4) ]
end

end

# Layer bounds
$layer_bounds =
{
'Ether' => [
            ['type', ETHERTYPE_IPv4, IP]
           ],

'ClassicBSDLoopback' => [
                         ['header', BSDLOOPBACKTYPE_IPv4, IP]
                        ],

'OpenBSDLoopback' => [
                      ['header', BSDLOOPBACKTYPE_IPv4, IP]
                     ],

'IP' => [
         ['proto', IPPROTO_ICMP, ICMP],
         ['proto', IPPROTO_TCP, TCP],
         ['proto', IPPROTO_UDP, UDP]
        ],
    }

# One day, this will be computed automatically :)
DISSECTOR_LIST = [Ether, IP, ICMP, Raw, TCP, UDP, ClassicBSDLoopback,
                  OpenBSDLoopback]
end
