$: << "specialized"
require "capture"
require "specialized/dot11"

module BaflleRecv  
  def eval(interface)
    @flags = Array.new(256, 0)
    @macs = {}
    Capture.open(interface) do |capture|
      capture.each do |packet|
        packet = packet[0..-5]
        packet = Radiotap.new(packet)
        packet = packet.payload
        
        next unless packet.type == 0
        next unless packet.subtype == 0x5
        next unless packet.addr1 =~ /ba:aa:ad:..:..:../
        #next unless packet.addr2 == "00:12:0E:51:AC:55"
        
        next if @macs.has_key?(packet.addr1)
        
        flags = packet.addr1.split(":", 6)[5].to_i(16)
        @flags[flags] = @flags[flags] + 1
        @macs[packet.addr1] = true
      end
    end
  end
end

include BaflleRecv # put it in the kernel
