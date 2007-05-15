require 'bit_struct_ng'

class Dot11 < BitStruct
  unsigned    :subtype, 4, 'Subtype'
  enum        :type, 2, 'Type', :spec => ['Management', 'Control', 'Data', 'Reserved']
  unsigned    :proto, 2, 'Protocol'
  flags       :fc, 8, 'Frame Control', :spec => ['to-DS', 'from-DS', 'MF', 'retry', 'pw-mgt', 'MD', 'wep', 'order']
  unsigned    :id, 16, "ID"
  hex_octets  :addr1, 48, "Address 1"
  hex_octets  :addr2, 48, "Address 2", :applicable => proc {|instance| if instance.type == 1 then [0xb, 0xa, 0xe, 0xf].include?(instance.subtype) else true end}
  hex_octets  :addr3, 48, "Address 3", :applicable => proc {|instance| [0, 2].include?(instance.type)}
  unsigned    :sc, 16, "SC", :endian => :little, :applicable => proc {|instance| instance.type != 1}
  hex_octets  :addr4, 48, "Address 4", :applicable => proc {|instance| instance.type == 2 && (instance.fc & 0x3 == 0x3)}
  nest        :payload, 
end

a = Dot11.new

a.type = 'Data'
a.subtype = 0xa
a.fc = ['to-DS', 'MF']
p a
a.fc |= ['wep']

p a
p a.fc