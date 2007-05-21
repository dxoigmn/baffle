
class Packet
  class TextField < Field
    def get(instance, buffer)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      
      if offset_byte + length_byte > buffer.length
        return options[:default] || options["default"] || nil
      end
      
      buffer[byte_range].sub(/\0*$/, "").to_s
    end
    
    def set(instance, buffer, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      val_byte_range = 0..length_byte-1
      
      val = value.to_s
      if val.length < length_byte
        val += "\0" * (length_byte - val.length)
      end
      buffer[byte_range] = val[val_byte_range]
    end
  end
  
  class << self
    def text(name, length, *rest)
      options = parse_options(rest, name, TextField)
      add_field(name, length, options)
    end

  end
end
