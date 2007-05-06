require 'bit-struct'

class BitStruct
  class OptionalField < Field
    def class_name
      @child.class_name
    end
    
    def add_accessors_to(cl, attr = name)
      
    end
  end
    
  class BitEnumField < UnsignedField
    def BitEnumField.class_name
      "BitEnumField"
    end
    
    def initialize(*args)
      super(*args)
      @spec = args[4][:spec]
    end
    
    def inspect_in_object(obj, opts)
      value = obj.send(name)
      
      @spec[value]
    end
  end

  class FlagField < UnsignedField
    def FlagField.class_name
      "FlagField"
    end
    
    def initialize(*args)
      super(*args)
      
      @spec = args[4][:spec]
    end
    
    def inspect_in_object(obj, opts)
      value = obj.send(name)
      
      set_flags = []
      
      size.times do |i|
        set_flags << @spec[i] if value[i] == 1
      end
      
      "(#{set_flags.join(" | ")})"
    end
  end
  
  class << self
    def bit_enum_field(name, length, *rest)
      opts = parse_options(rest, name, BitEnumField)
      add_field(name, length, opts)
    end
    
    def flag_field(name, length, *rest)
      opts = parse_options(rest, name, FlagField)
      add_field(name, length, opts)      
    end
    
    # Add a field to the BitStruct (usually, this is only used internally).
    def add_field(name, length, opts = {})
      round_byte_length ## just to make sure this has been calculated
      ## before adding anything
      p opts
      name = name.to_sym
      
      if @closed
        raise ClosedClassError, "Cannot add field #{name}: " +
          "The definition of the #{self.inspect} BitStruct class is closed."
      end

      if fields.find {|f|f.name == name}
        raise FieldNameError, "Field #{name} is already defined as a field."
      end

      if instance_methods(true).find {|m| m == name}
        if opts[:allow_method_conflict] || opts["allow_method_conflict"]
          warn "Field #{name} is already defined as a method."
        else
          raise FieldNameError,"Field #{name} is already defined as a method."
        end
      end
      
      field_class = opts[:field_class]
      
      prev = fields[-1] || NULL_FIELD
      
      if prev.applicable
        offset = proc { |prev| prev.offset + prev.length }
      else
        offset = prev.offset + prev.length
      end
      
      field = field_class.new(prev, offset, length, name, opts)
      field.add_accessors_to(self)
      fields << field
      own_fields << field
      @bit_length += field.length
      @round_byte_length = (bit_length/8.0).ceil

      if @initial_value
        diff = @round_byte_length - @initial_value.length
        if diff > 0
          @initial_value << "\0" * diff
        end
      end

      field
    end
  end
end

class Dot11 < BitStruct
  unsigned :subtype, 4, 'Subtype'
  bit_enum_field :type, 2, 'Type', :spec => ["Management", "Control", "Data", "Reserved"]
  unsigned :proto, 2, 'Protocol'
  flag_field :fc_field, 8, 'FCField', :spec => ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]
  unsigned :id, 16, 'ID'
  hex_octets :addr1, 48, 'Address 1'
  hex_octets :addr2, 48, 'Address 2', :applicable => proc { |parent| if parent.type == 1 then [0xb, 0xa, 0xe, 0xf].include?(parent.subtype) else true end }
  hex_octets :addr3, 48, 'Address 3'
  unsigned :sc, 16, 'SC', :endian => :little
  hex_octets :addr4, 48, 'Address 4'
end

a = Dot11.new

a.type = 3
a.fc_field = 57
a.addr1 = "aa:bb:cc:11:22:44"

p a