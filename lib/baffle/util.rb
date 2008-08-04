require 'rubygems'
require 'rb-pcap'
require 'rb-lorcon'

module Baffle
  def self.emit(options, injection_proc, injection_values)
    @device = Lorcon::Device.new(options.inject, options.driver)
    @device.fmode      = "INJMON"
    @device.channel    = options.channel
    
    injection_values << [nil] if injection_values.empty?

    injection_values.each do |args|
      packet = injection_proc.call(options, *args)
      puts "sending: #{packet.inspect}"
      send_p(packet.data)
      sleep 0.05
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
