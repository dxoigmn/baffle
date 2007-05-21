class Packet
  class NestedField < Field
    def get(instance, buffer)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      nested_class = nested_class(instance)

      if nested_class != nil
        nested_class.new(buffer[byte_range])
      else
        nil
      end
    end
    
    def set(instance, buffer, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      buffer[byte_range] = value.data
    end
    
    def length(instance)
      nested_class = nested_class(instance)
      
      if nested_class != nil
        nested = nested_class.new()
        nested.length * 8
      else
        0
      end
    end
    
    private
    def nested_class(instance)
      nested_class = options[:nested_class]
      nested_class = nested_class[instance  ] if nested_class.kind_of?(Proc)
      
      nested_class
    end
  end
  
  class << self
    def nest(name, length, *rest)
      options = parse_options(rest, name, NestedField)
      add_field(name, length, options)
    end
  end
end
