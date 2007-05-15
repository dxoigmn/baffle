
class BitStruct
  class NestedField < Field
    def get(instance)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      

    end
    
    def set(instance, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte


    end
    
    def empty!(instance)
      
    end
  end
  
  class << self
    def nest(name, length, *rest)
      opts = parse_options(rest, name, NestedField)
      add_field(name, length, opts)
    end
    alias struct nest
  end
end
