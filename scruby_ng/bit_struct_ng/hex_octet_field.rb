
class BitStruct
  class HexOctetField < OctetField
    SEPARATOR = ":"
    FORMAT    = "%02x"
    BASE      = 16
  end
  
  class << self
    def hex_octets(name, length, *rest)
      opts = parse_options(rest, name, HexOctetField)
      add_field(name, length, opts)
    end
  end
end
