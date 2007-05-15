
class BitStruct
  class EnumField < UnsignedField
    def get(instance)
      options[:spec][super(instance)]
    end
    
    alias old_set set
    
    def set(instance, value)
      super(instance, options[:spec].index(value) || raise("undefined value #{value}"))
    end
    
    def empty!(instance)
      old_set(instance, 0)
    end
  end
  
  class << self
    def enum(name, length, *rest)
      opts = parse_options(rest, name, EnumField)
      add_field(name, length, opts)
    end
  end
end
