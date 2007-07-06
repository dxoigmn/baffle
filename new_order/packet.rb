require 'field'

$PREVENT_INAPPLICABLE_FIELDS = false

class Packet
  undef type
  
  def length
    data.length
  end
  
  alias size length
  
  def data
    construct
  end
  
  alias to_s data
  
  def data=(str)
    dissect(str)
  end
  
  def initialize(value = nil)
    @field_values = {}

    if value.kind_of? Hash
      value.each do |field, value|
        send "#{field}=", value
      end
    else
      self.data = value
    end
  end
  
  def /(other)
    fail "Packet cannot contain a nested field." if self.class.nested_field == nil
    
    duplicate = dup
    
    # Find nested field that is not yet filled in.
    unnested = duplicate
    unnested = unnested.nested until unnested.nested == nil
    
    # Fill in the nested field.
    unnested.nested = other
    
    duplicate
  end
  
  def field_values
    @field_values
  end

  # FIXME: There is an logical in this code. Elts can be reordered and thus we should account for that.  
  def =~(packet)
    return true if packet == nil  
    return false if self.class != packet.class
  
    # Make sure all packet values are equal to our values.
    packet.field_values.each do |name, value|
      my_value = self.send(name)
      return false if my_value != value
    end
    
    # Make sure all nested values are equal to our nested values (recurse).
    #puts "Evaluating nested values for #{nested.class} vs #{packet.nested}."
    nested =~ packet.nested
  end
  
  def nested
    return nil if self.class.nested_field == nil
    
    get_field_value self.class.nested_field.name
  end
  
  def nested=(value)
    fail "Packet cannot contain a nested field." if self.class.nested_field == nil
    
    set_field_value self.class.nested_field.name, value
  end
  
  private
    
  def construct
    buffer = ""
    
    #puts "Constructing #{self.class}"
    
    self.class.fields.each do |field|
      next if !field.applicable?(self)
      
      if field.kind_of?(NestedField)
        #puts "Skipping nested field."
        next if get_field_value(field.name) == nil
      end
      
      offset = (field.offset(self) / 8.0).ceil
      length = (field.length(self) / 8.0).ceil

      #puts "#{self.class}: #{field.name}[#{offset} + #{length}] requires #{offset + length} bytes...#{buffer.length} bytes in buffer"

      buffer << "\0" * (offset + length - buffer.length)
      
      value = get_field_value(field.name)
      field.set(self, buffer, value) if value
    end

    if @nested_field
      buffer << @nested_field.data
    end
    
    buffer
  end
  
  def dissect(buffer)
    buffer ||= ""
    
    #puts "#{self.class}: Dissecting #{buffer.length} bytes in buffer."
    #puts pretty_print(buffer)

    self.class.fields.each do |field|
      
      value = field.get(self, buffer)
      #puts "#{self.class}: Trying to get data for #{field.name} => #{value.inspect}"
      
      if (!field.kind_of?(NestedField)) || 
         (field.kind_of?(NestedField) && value != nil)
        set_field_value(field.name, value)
      end
    end
  end
 
  def get_field_value(field_name)
    @field_values[field_name]
  end
  
  def set_field_value(field_name, value)
    @field_values[field_name] = value
  end

  def method_missing(name, *args)
    field_name = name.id2name.sub(/=$/, '').intern
    
    if self.class.has_field?(field_name)
      if $PREVENT_INAPPLICABLE_FIELDS && !self.class.field(field_name).applicable?(self)
        raise "The requested field #{field_name.id2name} is not applicable to #{self.inspect}"
      end
      
      if field_name == name
        get_field_value(field_name)
      else
        set_field_value(field_name, args[0])
      end
    else
      raise NoMethodError.new("undefined method #{name.id2name} on #{self.class.pretty_name}")
    end
  end

  class << self
    attr_accessor :pretty_name
    attr_accessor :nested_field
    
    def name(pretty_name)
      @pretty_name = pretty_name
    end
    
    def bind_to(parent, conditions)
      raise "Not implemented: bind_to"
    end
    
    def field(name)
      @fields[@field_hash[name]]
    end
    
    def fields
      @fields ||= []
    end
    
    def field_hash
      @field_hash ||= {}
    end
    
    def has_field?(field)
      field_hash.has_key?(field)
    end

    def add_field(name, length, options = {})
      field_class = options[:field_class]
      options[:length] = length
      
      field = field_class.new(self, name, options)
      
      if field_class == NestedField
        fail "Only one nested field allowed." if @nested_field != nil
        @nested_field = field
      end
      
      field_hash[name] = fields.size
      fields << field
      field
    end

    def parse_options(array, default_name, default_field_class)
      options = array.grep(Hash).first || {}

      options[:display_name] = (array.grep(String).first || default_name).to_s
      options[:field_class] = array.grep(Class).first || default_field_class

      options
    end
  end
end

class Raw < Packet
  name "Raw Data"
end

# TODO: add thing to combine all applicable combinations and enumerate them