module Baffle
  class PacketSet
    Pair = Struct.new(:name, :value)
  
    attr_accessor :packet_class
  
    def initialize(klass, parameters)
      @fields = []

      @packet_class = klass

      parameters.each_pair do |key, value|
        @fields << Pair.new(key, value)
      end
        
      @field_sizes = @fields.map do |field|
        if field.value.respond_to?(:size) && !(field.value.kind_of?(String) || field.value.kind_of?(Numeric))
          field.value.size
        elsif field.value.respond_to?(:entries)
          field.value.entries.size
        else
          field.value = [field.value]
          1
        end
      end
    end
  
    def [](index)          
      indices = @field_sizes.inject([]) do |accumulator, size|
        remainder = index % size 
        index /= size # yeah textmate isn't perfect and that's why I need this slash: /      
        accumulator << remainder
      end
    
      field_hash = {}
    
      indices.each_with_index do |index, i|  
        value = @fields[i].value
      
        if value.kind_of?(Array) or value.kind_of?(Range)
          field_hash[@fields[i].name] = @fields[i].value.entries[index]
        else
          field_hash[@fields[i].name] = @fields[i].value
        end      
      end
    
      out = @packet_class.new(field_hash)
    
      out
    end
  
    def size
      @field_sizes.inject(1) { |product, size| size * product }
    end
  
    def each(prefix = [])
      size.times do |i|
        yield self[i]
      end
    end

    def include?(packet)
      # This is horrrrrribly inefficient. FIXME
      each do |pkt|
        return true if packet == pkt
      end
    
      false
    end
  
    def to_filter
      raise "Not implemented: to_filter"
    
      filter = ""
    
      @fields.each do |field|
        packet_field = @packet_class.field(field.name)
      
        p packet_field.offset()
      end
    
      filter
    end
  end
end