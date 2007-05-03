require 'bit-struct'

class BitStruct
  class BitEnumField < UnsignedField
    def BitEnumField.class_name
      "BitEnumField"
    end
    
    def initialize(*args)
      super(*args)
      
      @spec = args[3][:spec]
    end
    
    def inspect_in_object(obj, opts)
      value = obj.send(name)
      
      @spec[value]
    end
  end

  class FlagField < UnsignedField
    def FlagField.class_name
      "FlagField"
    end
    
    def initialize(*args)
      super(*args)
      
      @spec = args[3][:spec]
    end
    
    def inspect_in_object(obj, opts)
      value = obj.send(name)
      
      set_flags = []
      
      size.times do |i|
        set_flags << @spec[i] if value[i] == 1
      end
      
      "(#{set_flags.join(" | ")})"
    end
  end
  
  class << self
    def bit_enum_field(name, length, *rest)
      opts = parse_options(rest, name, BitEnumField)
      add_field(name, length, opts)
    end
    
    def flag_field(name, length, *rest)
      opts = parse_options(rest, name, FlagField)
      add_field(name, length, opts)      
    end
  end
end

class Dot11 < BitStruct
  unsigned :subtype, 4, 'Subtype'
  bit_enum_field :type, 2, 'Type', :spec => ["Management", "Control", "Data", "Reserved"]
  unsigned :proto, 2, 'Protocol'
  flag_field :fc_field, 8, 'FCField', :spec => ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]
  unsigned :id, 16, 'ID'
  hex_octets :addr1, 48, 'Address 1'
  hex_octets :addr2, 48, 'Address 2'
  hex_octets :addr3, 48, 'Address 3'
  unsigned :sc, 16, 'SC', :endian => :little
  hex_octets :addr4, 48, 'Address 4'
 
=begin 
  def init
    @protocol = 'TCP'
    @fields_desc = [ 
      BitField('subtype', 0, 4),
      BitEnumField("type", 0, 2, ["Management", "Control", "Data", "Reserved"]),
      BitField("proto", 0, 2),
      FlagsField("FCfield", 0, 8, ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]),
      ShortField("ID",0),
      MACField("addr1", ETHER_ANY),
      Dot11Addr2MACField("addr2", ETHER_ANY),
      Dot11Addr3MACField("addr3", ETHER_ANY),
      Dot11SCField("SC", 0),
      Dot11Addr4MACField("addr4", ETHER_ANY) 
    ]      
  end
=end

end

a = Dot11.new

a.type = 3
a.fc_field = 57
a.addr1 = "aa:bb:cc:11:22:44"

p a