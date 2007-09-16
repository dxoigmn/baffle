class PacketSet
  Pair = Struct.new(:name, :value)
  
  attr_accessor :packet_class
  attr_accessor :randomize
  
  def initialize(klass, parameters)
    @fields = []

    @packet_class = klass

    parameters.each_pair do |key, value|
      @fields << Pair.new(key, value)
    end
        
    @field_sizes = @fields.map do |field|
      if field.value.respond_to?(:size) && !(field.value.kind_of?(String) || field.value.kind_of?(Numeric) || field.value.kind_of?(Packet))
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
    
    out = @packet_class.new
    
    indices.each_with_index do |index, i|
      value = @fields[i].value
      
      if value.kind_of?(Array) or value.kind_of?(Range)
        out.send((@fields[i].name.to_s + "=").intern, @fields[i].value.entries[index])
      elsif value.kind_of?(PacketSet) # Could be done more simply by making PacketSet implement enumerable
	out.send((@fields[i].name.to_s + "=").intern, @fields[i].value[index])
      else
        out.send((@fields[i].name.to_s + "=").intern, @fields[i].value)
      end
    end
    
    out
  end
  
  def size
    @field_sizes.inject(1) { |product, size| size * product }
  end
  
  def each(prefix = [])
    indices = 0..size
    indices = indices.entries.sort_by { rand } if @randomize

    indices.times do |i|
      yield self[i]
    end
  end
  
  def each_with_index
    indices = 0..size
    indices = indices.entries.sort_by { rand } if @randomize
  
    indices.each do |i|
      yield self[i], i
    end
  end

  def include?(packet)
    # This is horrrrrribly inefficient (but we never use it, so it's ok)
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
