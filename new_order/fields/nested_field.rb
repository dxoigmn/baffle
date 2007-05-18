class Packet
  class NestedField < Field
    def get(instance, buffer)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      nested_class = options[:class]
      
      nested_class = nested_class[instance] if nested_class.kind_of?(Proc)
      
      nested_class.new(instance[byte_range])
    end
    
    def set(instance, buffer, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      
    end
    
    def length(instance)
      
      instance.send(name).length
    end
    
  end
  
  class << self
    def nest(name, length, *rest)
      options = parse_options(rest, name, NestedField)
      add_field(name, length, options)
    end
  end
end
