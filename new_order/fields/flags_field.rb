
class Packet
  class FlagsField < UnsignedField
    #def get(instance, buffer)
    #  value = super(instance, buffer) || 0
    #  ret = [] 
    #  options[:spec].each_with_index do |item, index| 
    #    ret << item if value[index] == 1
    #  end
    #  
    #  ret
    #end

    def set(instance, buffer, value)
      if value.kind_of?(Integer)
        super(instance, buffer, value)
      else
        flags = 0
        options[:spec].each_with_index { |item, index| flags |= 2 ** index if value.include?(item)}
        super(instance, buffer, flags)
      end
    end
  end
  
  class << self
    def flags(name, length, *rest)
      options = parse_options(rest, name, FlagsField)
      add_field(name, length, options)
    end
  end
end
