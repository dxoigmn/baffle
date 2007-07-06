class Packet
  class ArrayField < NestedField
    def get(instance, buffer)
      offset_byte = offset(instance) / 8
      byte_range = offset_byte..-1
      
      if offset_byte >= buffer.length
        return options[:default] || options["default"] || nil
      end

      nested_class = nested_class(instance)
      buffer = buffer[byte_range]
      array = []

      return nil if nested_class == nil
  
      while buffer && buffer.length > 0
        nested = nested_class.new(buffer)
        array << nested
        byte_range = nested.length..-1
        buffer = buffer[byte_range]
      end
      
      array      
    end
    
    def set(instance, buffer, values)
      offset_byte = offset(instance) / 8
      
      fail "Value must be an array" unless values.kind_of?(Array)
      
      values.each do |value|
        length_byte = value.length
        last_byte = offset_byte + length_byte
        byte_range = offset_byte..last_byte
         
        buffer[byte_range] = value.data
        
        offset_byte += length_byte
      end
    end
    
    def length(instance)
      nested = instance.send(:get_field_value, name)
      
      size = 0
      
      nested.each do |nest|
        size += nest.length
      end
            
      size * 8
    end
        
    private
    def nested_class(instance)
      nested_class = options[:nested_class]
      nested_class = nested_class[instance  ] if nested_class.kind_of?(Proc)
      
      nested_class
    end
  end
  
  class << self
    def array(name, length, *rest)
      options = parse_options(rest, name, ArrayField)
      add_field(name, length, options)
    end
  end
end