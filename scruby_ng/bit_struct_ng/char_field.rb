
class BitStruct
  class CharField < Field
    def get(instance)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      
      instance[byte_range].to_s
    end
    
    def set(instance, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      val_byte_range = 0..length_byte-1
      
      
      val = value.to_s
      if val.length < length_byte
        val += "\0" * (length_byte - val.length)
      end

      instance.ensure_length(last_byte)
      instance[byte_range] = val[val_byte_range]
    end
    
    def empty!(instance)
      set(instance, "")
    end
  end
  
  class << self
    def char(name, length, *rest)
      opts = parse_options(rest, name, CharField)
      add_field(name, length, opts)
    end
    alias string char
  end
end
