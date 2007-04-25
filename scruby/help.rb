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

# General help
def Scruby.help(command = nil)

  if command.nil?
    print <<EOF
This is Scruby, a portable, customizable packet creation and sending/sniffing tool written in Ruby. It was tested on NetBSD and GNU/Linux, and should theoretically work on some other platforms such as FreeBSD, OpenBSD, Mac OS X and proprietary Unixes.

See http://sylvainsarmejeanne.free.fr/projects/scruby for more information.

With Scruby, you can:
- create custom packet: p=IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
- send custom packets at layer 2: sendp(Ether(:src=>"00:11:22:33:44:55")/p)
- sniff on an interface: sniff(:iface=>"eth1")
- dissect a string to a recreate the packet: s=str(p);puts "string=\#{s.inspect}\\nresult=\#{IP(s)}"

Available dissectors:
#{DISSECTOR_LIST_S.inspect}

Available functions (type "help '<function>'" to have detailed information):
#{FUNCTION_LIST.inspect}
EOF
  else
    # Executing the specific help function
    eval(command.to_s + '_help')	
  end
end

# Help on str
def Scruby.str_help
    print <<EOF
This function transforms a packet into a string ready to be sent on the wire (that is to say, it "packs" it).

example> p=IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> str(p).inspect
"E\\000\\000:\\000\\000\\000\\000@\\006\\035\\374\\001\\002\\003\\004\\321U\\207g\\004\\000\\000P\\000\\000\\000\\000\\000\\000\\000\\000P\\002 \\000_\\036\\000\\000GET / HTTP 1.0\\r\\n\\r\\n"
EOF
end

# Help on sniff
def Scruby.sniff_help

    print <<EOF
This function captures packets on an interface. The default capture interface is stored in $conf.iface, currently "#{$conf.iface}".

Without any argument, sniff captures on the default interface:
example> sniff
listening on eth0
1158608918.45960 <Ethernet dst=00:11:22:33:44:55 src=55:44:33:22:11:00 |><IPv4 len=84 flags_offset=16384 proto=1 chksum=0x7c0f src=1.2.3.4 dst=4.3.2.1 |><ICMP chksum=17905 id=16922 seq=1 |>

1158608918.124147 <Ethernet dst=55:44:33:22:11:00 src=00:11:22:33:44:55 |><IPv4 len=84 flags_offset=16384 ttl=244 proto=1 chksum=0xc80e src=4.3.2.1 dst=1.2.3.4 |><ICMP type=0 chksum=19953 id=16922 seq=1 |>

The following arguments are available (with the default values between brackets):
- iface: the interface to listen on ($conf.iface, currently "#{$conf.iface}")
- prn: a function that will be called for each packet received (:sniff_simple)
- filter: a PCAP filter (undef)
- count: the number of packets to capture. An argument less than or equal to 0 will read "loop forever" (-1)
- promisc: capture in promiscuous mode or not ($conf.promisc, currently "#{$conf.promisc}")
- timeout: capture timeout in milliseconds (#{TIMEOUT}, seems not to work?)
- store: not implemented yet
- offline: not implemented yet

The prn argument is the most interesting one, it allows you to customize the behaviour of the sniff function:

example> def Scruby.my_prn(pcap, packet) puts "GOT ONE: raw=|\#{packet.inspect}|" end
example> sniff(:iface=>"eth1", :prn=>:my_prn, :filter=>"icmp", :count=>2)
listening on eth0
GOT ONE: raw=|"\000\a\313\fg\246\000Pp4\210\264\b\000E\000\000T\000\000@\000@\001\030KR\357\313I\324\e0\n\b\000\336\t4\031\000\001\001\202\252ED\021\v\000\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\e\034\035\036\037 !\"\#$%&'()*+,-./01234567"|

Note that by default, packets captured are not stored in memory for performance reason. To stop sniffing, press ^C.
EOF
end

# Help on send
def Scruby.send_help
    print <<EOF
This function sends a packet at layer 3 on the default interface ($conf.iface, currently "#{$conf.iface}"). If not specified, the Ethernet destination is $conf.gateway_hwaddr (currently "#{$conf.gateway_hwaddr}". 

If Libdnet is available, source IP address is automatically filled according to this interface.

example> p=IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> send(p)
Sent.
EOF
end

# Help on sendp
def Scruby.sendp_help
    print <<EOF
This function sends a packet at layer 2 on the default interface ($conf.iface, currently "#{$conf.iface}"). If not specified, the Ethernet destination will be $conf.gateway_hwaddr (currently "#{$conf.gateway_hwaddr}").

If Libdnet is available, source Ethernet address and source IP address are automatically filled according to this interface.

example> p=Ether(:src=>"00:11:22:33:44:55")/IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> sendp(p)
Sent on eth0.
EOF
end

end
