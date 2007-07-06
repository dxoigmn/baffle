require "dot11"

header = Dot11.new(:subtype => 8, :type => 0, :addr1 => "ff:ff:ff:ff:ff:ff", 
                   :addr2 => "00:0b:86:80:e4:e0", :addr3 => "00:0b:86:80:e4:e0", 
                   :sc => 0x1f0)
beacon = Dot11Beacon.new(:timestamp => 0x000002B69AF8433B, :beacon_interval => 0x0064, :capabilities => 0x2100)
ssid = Dot11Elt.new(:id => 0, :info_length => 15, :info => "Kiewit Wireless")
rates = Dot11Elt.new(:id => 1, :info_length => 4, :info => "#{0x82.chr}#{0x84.chr}#{0x0b.chr}#{0x16.chr}")
ds = Dot11Elt.new(:id => 3, :info_length => 1, :info => 0x0b.chr)

data = (header/beacon/ssid/rates/ds).data

data.each_byte do |byte|
  print byte.to_s(16), " "
end
puts " "

packet = Dot11.new(data)
packet.data.each_byte do |byte|
  print byte.to_s(16), " "
end
puts " "

if packet.data == data
  puts "PASSED!"
else
  puts "FAILED!"
end

puts "type => #{header.type}"
