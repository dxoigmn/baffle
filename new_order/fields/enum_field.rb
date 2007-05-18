
class Packet
  class EnumField < UnsignedField
    #def get(instance)
    #  options[:spec][super(instance)]
    #end
    
    def set(instance, buffer, value)
      if value.kind_of?(Integer)
        super(instance, buffer, value)
      else
        super(instance, buffer, options[:spec].index(value) || raise("undefined value #{value}"))
      end
    end
  end
  
  class << self
    def enum(name, length, *rest)
      options = parse_options(rest, name, EnumField)
      add_field(name, length, options)
    end
  end
end
