require 'rubygems'
require 'rb-pcap'
require 'rb-lorcon'

module Baffle
  def self.emit(interface, driver, channel, stuff, sleep_interval = 0.5)
    @device = Lorcon::Device.new(interface, driver)
    @device.fmode      = "INJMON"
    @device.channel    = channel
    
    case stuff
      when Dot11::PacketSet
        local_mac = nil #0xbaaaad000000
        stuff.each_with_index do |packet, index|
          local_mac ||= packet.addr2.to_i
          local_mac = (local_mac & 0xFFFFFFFF0000) | index
          packet.addr2 = local_mac
          #puts "emitting"
          #p packet

          send_p packet.data
          sleep sleep_interval
        end
      when Dot11::Packet
        send_p stuff
    end
  end  
  
  def self.send_p(packet)
    @device.write(packet, 1, 0)
  end
  
  def self.sniff(*params)
    Capture.open(*params) do |capture|
      capture.each do |packet|
        packet = packet[0..-5]
        packet = Dot11::Radiotap.new(packet)
        packet = packet.payload

        yield packet        
      end
    end
  end
end