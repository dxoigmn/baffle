require File.join(File.dirname(__FILE__), 'lib/capture/capture')
require 'Lorcon'

module Baffle
  def self.emit(interface, driver, channel, stuff, sleep_interval = 0.5)
    @device = Lorcon::Device.new(interface, driver, 11)
    
    case stuff
      when PacketSet
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
      when Packet
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
        packet = Radiotap.new(packet)
        packet = packet.payload

        yield packet        
      end
    end
  end
end
