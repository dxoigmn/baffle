class Packet
  class HexOctetField < OctetField
    SEPARATOR = ":"
    FORMAT    = "%02x"
    BASE      = 16
  end
  
  class << self
    def hex_octets(name, length, *rest)
      options = parse_options(rest, name, HexOctetField)
      add_field(name, length, options)
    end
  end
end
