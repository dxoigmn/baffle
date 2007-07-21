require 'packetset'
require 'dot11'

a = PacketSet.new(Dot11, :type => [1, 2], :subtype => 0..5)

a.each do |packet|
  puts packet
end