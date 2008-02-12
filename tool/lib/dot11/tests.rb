require 'dot11'

include Baffle

def test(klass, raw, packet, test_desc)
  dissector = (klass.new(raw) == packet)
  builder = (packet.data == raw)
  
  puts "#{klass} dissector #{dissector ? 'passed' : 'failed'} on #{test_desc}"
  puts "#{klass} builder #{builder ? 'passed' : 'failed'} on #{test_desc}"
end

#####################################################################################

beacon_raw = "\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x01\xe3\x41\xbd\x6e\x00\x01\xe3\x41\xbd\x6e\x00\x0e"
beacon = Dot11.new(:type => 0, 
                   :subtype => 8, 
                   :version => 0, 
                   :flags => 0, 
                   :duration => 0, 
                   :addr1 => "ff:ff:ff:ff:ff:ff",
                   :addr2 => "00:01:e3:41:bd:6e",
                   :addr3 => "00:01:e3:41:bd:6e",
                   :sc => 0x0e00)

test(Dot11, beacon_raw, beacon, "beacon frame")

#####################################################################################

data_raw = "\x08\x42\x00\x00\xff\xff\xff\xff\xff\xff\x00\x01\xe3\x41\xbd\x6e\x00\x01\xe3\x42\x9e\x2b\x40\x07"
data = Dot11.new(:type => 2,
                 :subtype => 0,
                 :version => 0,
                 :flags => 0x42,
                 :duration => 0,
                 :addr1 => "ff:ff:ff:ff:ff:ff",
                 :addr2 => "00:01:e3:41:bd:6e",
                 :addr3 => "00:01:e3:42:9e:2b",
                 :sc => 0x0740)

test(Dot11, data_raw, data, "data frame")

#####################################################################################

complete_beacon_raw = "\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x01\xe3\x41\xbd\x6e" + 
                      "\x00\x01\xe3\x41\xbd\x6e\xf0\x02\x86\xf1\x1b\x6a\x02\x00\x00\x00" + 
                      "\x64\x00\x11\x04\x00\x09\x6d\x61\x72\x74\x69\x6e\x65\x74\x33\x01" + 
                      "\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x0b\x05\x04\x00\x01" + 
                      "\x00\x00\x2a\x01\x04\x2f\x01\x04\x32\x04\x0c\x12\x18\x60\xdd\x06" + 
                      "\x00\x10\x18\x01\x01\x00\xdd\x16\x00\x50\xf2\x01\x01\x00\x00\x50" + 
                      "\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02"
complete_beacon = Dot11.new(:type => 0,
                            :subtype => 8,
                            :version => 0,
                            :flags => 0,
                            :duration => 0,
                            :addr1 => "ff:ff:ff:ff:ff:ff",
                            :addr2 => "00:01:e3:41:bd:6e",
                            :addr3 => "00:01:e3:41:bd:6e",
                            :sc => 0x02f0) /
                  Dot11Beacon.new(:timestamp => 0x26a1bf186,
                                  :beacon_interval => 0x64,
                                  :capabilities => 0x1104) / 
                  Dot11Elt.new(:id => 0,
                               :info_length => 9,
                               :info => "martinet3") / 
                  Dot11Elt.new(:id => 1,
                               :info_length => 8,
                               :info => "\x82\x84\x8b\x96\x24\x30\x48\x6c") / 
                  Dot11Elt.new(:id => 3,
                               :info_length => 1,
                               :info => "\x0b") / 
                  Dot11Elt.new(:id => 5,
                               :info_length => 4,
                               :info => "\x00\x01\x00\x00") / 
                  Dot11Elt.new(:id => 42,
                               :info_length => 1,
                               :info => "\x04") / 
                  Dot11Elt.new(:id => 47,
                               :info_length => 1,
                               :info => "\x04") / 
                  Dot11Elt.new(:id => 50,
                               :info_length => 4,
                               :info => "\x0c\x12\x18\x60") / 
                  Dot11Elt.new(:id => 221,
                               :info_length => 6,
                               :info => "\x00\x10\x18\x01\x01\x00") / 
                  Dot11Elt.new(:id => 221,
                               :info_length => 22,
                               :info => "\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02")
 
test(Dot11, complete_beacon_raw, complete_beacon, "complete beacon frame")
p complete_beacon

#####################################################################################

acknowledgement_raw = "\xd4\x00\x00\x00\x00\x15\x00\x34\x18\x52"
acknowledgement = Dot11.new(:type => 1,
                            :subtype => 13,
                            :version => 0,
                            :flags => 0,
                            :duration => 0,
                            :addr1 => "00:15:00:34:18:52")

test(Dot11, acknowledgement_raw, acknowledgement, "acknowledgement frame")
puts("Passed to_i test") if acknowledgement.addr1.to_i == 0x1500341852
p acknowledgement

#####################################################################################

probereq_raw = "\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x16\xbc\x3d\xaa\x57\xff" + 
               "\xff\xff\xff\xff\xff\xb0\x00\x00\x09\x6d\x61\x72\x74\x69\x6e\x65\x74" + 
               "\x33\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x09\x32\x04\x30" + 
               "\x48\x60\x6c"
probereq = Dot11.new(:type => 0,
                     :subtype => 4,
                     :version => 0,
                     :flags => 0,
                     :duration => 0,
                     :addr1 => "ff:ff:ff:ff:ff:ff",
                     :addr2 => "00:16:bc:3d:aa:57",
                     :addr3 => "ff:ff:ff:ff:ff:ff",
                     :sc => 0x00b0) / 
           Dot11ProbeReq.new() /
           Dot11Elt.new(:id => 0, :info_length => 9, :info => "martinet3") / 
           Dot11Elt.new(:id => 1, :info_length => 8, :info => "\x82\x84\x8b\x96\x0c\x12\x18\x24") / 
           Dot11Elt.new(:id => 3, :info_length => 1, :info => "\x09") /
           Dot11Elt.new(:id => 50, :info_length => 4, :info => "\x30\x48\x60\x6c")

test(Dot11, probereq_raw, probereq, "probe request frame")
p probereq

#####################################################################################
