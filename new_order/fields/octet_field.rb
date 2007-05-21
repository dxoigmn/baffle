
class Packet
  class OctetField < CharField
    SEPARATOR = "."
    FORMAT    = "%d"
    BASE      = 10
    
    def get(instance, buffer)
      sep   = self.class::SEPARATOR
      base  = self.class::BASE
      fmt   = self.class::FORMAT
      
      ary = []
      chars = super(instance, buffer) || ""
      
      chars.each_byte do |c|
        ary << fmt % c
      end
      ary.join(sep)
    end
    
    def set(instance, buffer, value)
      sep   = self.class::SEPARATOR
      base  = self.class::BASE
      fmt   = self.class::FORMAT

      data = value.split(sep).map{|s|s.to_i(base)}.pack("c*")
      
      super(instance, buffer, data)
    end 
    
  end
  
  class << self
    def octets(name, length, *rest)
      options = parse_options(rest, name, OctetField)
      add_field(name, length, options)
    end
  end
end
