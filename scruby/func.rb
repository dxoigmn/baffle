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

# Converts a packet to a string
def Scruby.str(packet)
  return packet.tonet
end

# Sniff packets on an interface
def Scruby.sniff(args = Hash.new())

  # Default parameter values
  params = {
    :iface => $conf.iface,
    :prn => :sniff_simple,
    :filter => nil,
    :count => -1,
    :promisc => $conf.promisc,
    :timeout => TIMEOUT
  }

  # Overwriting default values with user-supplied ones
  params.merge!(args)

  # Can't sniff without a valid interface
  if params[:iface].nil?
    puts "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator."
    return
  end
  
  # OK, opening the interface with PCAP
  begin
    pcap = Pcap::open_live(params[:iface], MTU, params[:promisc], params[:timeout])
  rescue
    puts "Pcap: can't open device '#{params[:iface]}' (are you root/Administrator?)"
    return
  end
  
  # PCAP filtering
  if not params[:filter].nil?
    begin
      pcap.setfilter(params[:filter])
    rescue
      puts "Pcap: can't set filter '#{params[:filter]}'"
      return
    end
  end
  
  # Preparing sniffing
  puts "listening on #{params[:iface]}"
  
  # Sniffing in progress
  begin
    pcap.each do |packet|

      # Calling the method defined in "prn"
      Scruby.__send__(params[:prn], pcap, packet)

      # Handling the number of packets to process
      params[:count] -= 1
      if params[:count] == 0
        break
      end

    end

  # ^C to stop sniffing
  rescue Interrupt
    puts "\nStopped by user."

  rescue Exception => e
    puts "\nERROR: " + e
  end
end

# Default callback function for the sniff method (simple packet display)
def Scruby.sniff_simple(pcap, packet)

  # Getting the link type
  linktype = pcap.datalink

  # Getting current date and time (epoch)
  date_time = Time.new.to_f.to_s + ' '
  
  # Ethernet or Linux loopback
  if linktype == Pcap::DLT_EN10MB
    puts date_time + Ether(packet).to_s
    puts

  # Classic BSD loopback
  elsif linktype == Pcap::DLT_NULL
    puts date_time + ClassicBSDLoopback(packet).to_s
    puts
    
  # OpenBSD loopback
  elsif linktype == 12
    puts date_time + OpenBSDLoopback(packet).to_s
    puts
    
  # Unknown link type
  else
    puts "Unknown link type: #{linktype}"
    puts "raw packet=|#{packet.inspect}| "
    puts
  end
end

# Sends a packet at layer 3 (will not work yet)
def Scruby.send(packet)

    iface = $conf.iface

    # Can't do anything without a valid interface
    if iface.nil?
      puts "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator."
      return
    end

    # Sending the packet with sendp
    # If we're sending on a loopback interface, we must be careful
    # because of the different fake headers.
    # The loopback device is "lo" on Linux and "lo0" on BSD; there is
    # no loopback device on Windows.
    # On BSD, a 4-byte header is used for loopback and there is a
    # special case for OpenBSD; on Linux, it is an Ethernet header.
    if $IS_BSD and $conf.iface.include?(LOOPBACK_DEVICE_PREFIX)
      
      if $IS_OPENBSD
        sendp(OpenBSDLoopback()/packet)
      else
        sendp(ClassicBSDLoopback()/packet)
      end
    
    else
    	sendp(Ether()/packet)
    end
end

# Sends a packet at layer 2
def Scruby.sendp(packet)
  
  iface = $conf.iface
  promisc = $conf.promisc
  
  # Can't do anything without a valid interface
  if iface.nil?
    puts "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator."
    return
  end
  
  # Default values
  ip_default_src = IP().src
  ether_default_src = Ether().src
  ether_default_dst = Ether().dst
  
  layer3_src = ip_default_src
  layer2_src = ether_default_src
  layer2_dst = $conf.gateway_hwaddr

  # Getting source information with Libdnet if available
  #if $HAVE_LIBDNET
    #iface_info = Net::Libdnet::intf_get($conf.iface)
    
    #if iface_info.addr.nil?
    #  puts "Libdnet: interface '#{$conf.iface}' is not valid."
    #end
    
    # addr field is "a.b.c.d/mask", splitting at '/'
    #layer3_src = iface_info.addr.split(/\//)
    #layer2_src = iface_info.link_addr
  #end
  
  # Destination MAC is taken from the configuration. On Linux, if the
  # packet is to be sent on the loopback device, it must be null.
  if $IS_LINUX and $conf.iface.include?(LOOPBACK_DEVICE_PREFIX)
    layer2_dst = ether_default_src
  end
  
  # Modifying the Ethernet layer (only if the values are the default ones)
  # If the first layer is Ethernet and src/dst are the default values
  if packet.is_a?(Ether) and packet.dst == ether_default_dst
    packet.dst = layer2_dst

  # If packet is a Packet with Ethernet as a first layer
  elsif packet.layers_list[0].is_a?(Ether) and packet.layers_list[0].dst == ether_default_dst
    packet.layers_list[0].dst = layer2_dst
  end
  
  # Opening the interface
  begin
    pcap = Pcap::open_live(iface, MTU, $conf.promisc, TIMEOUT)
  rescue
    puts "Pcap: can't open device '#{iface}' (are you root/Administrator?)"
    return
  end
  
  # Packing the packet
  packet_string = packet.tonet
  
  # Sending the packet with PCAP
  begin
    pcap.inject(packet_string)
    puts "Sent on #{iface}."
  rescue
    puts "Pcap: error while sending packet on #{iface}"
  end
  
end

end
