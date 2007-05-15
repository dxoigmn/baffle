
class BitStruct
  class FlagsField < UnsignedField
    def get(instance)
      value = super(instance)
      ret = []
      options[:spec].each_with_index { |item, index| ret << item if value[index] == 1 }
      
      ret
    end
    
    alias old_set set
    
    def set(instance, value)
      val = 0
      
      options[:spec].each_with_index { |item, index| val |= 2 ** index if value.include?(item)}
      
      super(instance, val)
    end
    
    def empty!(instance)
      old_set(instance, 0)
    end
  end
  
  class << self
    def flags(name, length, *rest)
      opts = parse_options(rest, name, FlagsField)
      add_field(name, length, opts)
    end
  end
end
