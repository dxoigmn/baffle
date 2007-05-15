require 'bit_struct_ng'

class Test < BitStruct
  char :name, 80, "Name"
  hex_octets :mac, 48, "MAC Address"
end

a = Test.new

p a
p a.mac
p a.length

a.mac = "00:11:22:33:44:55"
p a
p a.length
p a.mac