require 'packetset'
require 'dot11'


data_raw = "\x08\x42\x00\x00\xff\xff\xff\xff\xff\xff\x00\x01\xe3\x41\xbd\x6e\x00\x01\xe3\x42\x9e\x2b\x40\x07"
data = Dot11.new(:type => 2,
                 :subtype => 0,
                 :version => 0,
                 :flags => 0x42,
                 :id => 0,
                 :addr1 => "ff:ff:ff:ff:ff:ff",
                 :addr2 => "00:01:e3:41:bd:6e",
                 :addr3 => "00:01:e3:42:9e:2b",
                 :sc => 0x0740)

a = Dot11.new(data_raw)

puts a
puts "\n"

a.addr1 = 42040000000000

puts a