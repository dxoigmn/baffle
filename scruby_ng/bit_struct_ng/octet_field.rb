
class BitStruct
  class OctetField < CharField
    SEPARATOR = "."
    FORMAT    = "%d"
    BASE      = 10
    
    def get(instance)
      sep   = self.class::SEPARATOR
      base  = self.class::BASE
      fmt   = self.class::FORMAT
      
      ary = []
      super(instance).each_byte do |c|
        ary << fmt % c
      end
      ary.join(sep)
    end
    
    def set(instance, value)
      sep   = self.class::SEPARATOR
      base  = self.class::BASE
      fmt   = self.class::FORMAT

      data = value.split(sep).map{|s|s.to_i(base)}.pack("c*")
      
      
      
      super(instance, data)
    end
    
    
  end
  
  class << self
    def octets(name, length, *rest)
      opts = parse_options(rest, name, OctetField)
      add_field(name, length, opts)
    end
    alias string char
  end
end
