require 'bit-struct/bit-struct'

class BitStruct
  # Class for nesting a BitStruct as a field within another BitStruct.
  # Declared with BitStruct.nest.
  class NestedField < Field
    def initialize(*args)
      super
    end
    
    def nested_class(instance)
      @nested_class ||= options[:nested_class] || options["nested_class"] || options[:nested_class][instance]
    end

    def describe(opts)
      if opts[:expand]
        opts = opts.dup
        opts[:byte_offset] = offset / 8
        opts[:omit_header] = opts[:omit_footer] = true
        nested_class.describe(nil, opts) {|desc| yield desc}
      else
        super
      end
    end

    def get(instance)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      val_byte_range = 0..length_byte - 1

      nc = nested_class(instance)
      
      nc.new(instance[byte_range])
    end

    def set(instance, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      val_byte_range = 0..length_byte - 1

      nc = nested_class(instance)
      
      if value.length != length_byte
        raise ArgumentError, "Size mismatch in nested struct assignment with value #{value.inspect}"   
      end
      
      if value.class != nc
        warn "Type mismatch in nested struct assignment with value #{value.inspect}"
      end     
      
      instance[byte_range] = value[val_byte_range]
    end
    
  end
  
  class << self
    def nest(name, nested_class, *rest)
      opts = parse_options(rest, name, NestedField)
      opts[:default] ||= nested_class.initial_value.dup
      opts[:nested_class] = nested_class
      field = add_field(name, nested_class.bit_length, opts)
      field
    end
    alias struct nest
  end
end
