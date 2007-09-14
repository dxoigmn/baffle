$: << "specialized"
require "packetset"
require "specialized/dot11"
require "Lorcon"

module BaflleSend
  def emit(interface, driver, stuff)
    @device = Lorcon::Device.new(interface, driver, 1)
    
    case stuff
      when PacketSet
        local_mac = 0xbaaaad000000
        stuff.each do |packet|
          packet.addr2 = local_mac
          local_mac += 1

          send_p packet.data
          sleep 0.5
        end
      when Packet
        send_p stuff
    end
  end  
  
  def send_p(packet)
    @device.write(packet, 1, 0)
  end
end

include BaflleSend # Put it in the kernel
