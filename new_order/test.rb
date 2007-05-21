require "dot11"

# Create an 802.11 header
packet = Dot11.new()
packet.subtype  = 8
packet.type     = 0
packet.proto    = 0
packet.fc       = 0
packet.id       = 0
packet.addr1    = "ff:ff:ff:ff:ff:ff"
packet.addr2    = "00:0b:86:80:e4:e0"
packet.addr3    = "00:0b:86:80:e4:e0"
packet.sc       = 0x01f0

# Create an 802.11 beacon
beacon = Dot11Beacon.new()
beacon.timestamp        = 0x000002B69AF8433B
beacon.beacon_interval  = 0x0064
beacon.capabilities     = 0x2100

# Create an 802.11 ssid
ssid = Dot11Elt.new()
ssid.id           = 0
ssid.info_length  = 15
ssid.info         = "Kiewit Wireless"

# Create an 802.11 rates
rates = Dot11Elt.new()
rates.id          = 1
rates.info_length = 4
rates.info        = "#{0x82.chr}#{0x84.chr}#{0x0b.chr}#{0x16.chr}"

# Create an 802.11 ds
ds = Dot11Elt.new()
ds.id           = 3
ds.info_length  = 1
ds.info         = 0x0b.chr

(packet/beacon/ssid/rates/ds).data.each_byte do |byte|
  print byte.to_s(16), " "
end
puts " "
