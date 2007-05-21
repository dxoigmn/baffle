class PacketSet
  Pair = Struct.new(:name, :value)
  
  def initialize(*parameters)
    @fields = []

    parameters[0].each_pair do |key, value|
      @fields << Pair.new(key, value)
    end
        
    @field_sizes = @fields.map do |field|
      if field.value.respond_to?(:size)
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
      index /= size #/      
      accumulator << remainder
    end
    
    hash = {}
    
    indices.each_with_index do |index, i|
      hash[@fields[i].name] = @fields[i].value.entries[index]
    end
    
    hash
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
    each do |pkt|
      return true if packet == pkt
    end
    
    false
  end
end
