$: << "specialized"
require "capture"
require "specialized/dot11"

module BaflleRecv  
  def sniff(*params)
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

include BaflleRecv # put it in the kernel
