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
  
  def data=(str)
    dissect(str)
  end
  
  def initialize(data="")
    @field_values = {}
    self.data = data
  end
  
  def /(other)
    raise "Packet cannot contain a nested field." if self.class.nested_field == nil
    
    duplicate = dup
    
    nested = duplicate
    
    while nested.send(:get_field_value, nested.class.nested_field.name) != nil
      nested = nested.send(:get_field_value, nested.class.nested_field.name)
    end
    
    nested.send(:set_field_value, nested.class.nested_field.name, other)
    
    duplicate
  end
  
  private
  
  def construct
    buffer = ""
    
    self.class.fields.each do |field|    
      next if !field.applicable?(self)
      
      if field.kind_of?(NestedField)
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
    self.class.fields.each do |field|
      if field.kind_of?(NestedField)
        next if get_field_value(field.name) == nil
      end
      
      value = field.get(self, buffer)
      set_field_value(field.name, value)
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
        # TODO: Throw exception if nested field is already set! (i.e. only allow 1 nested field)
        @nested_field = field
      end
      
      field_hash[name] = fields.size
      fields << field
      field
    end

    def parse_options(array, default_name, default_field_class)
      options = array.grep(Hash).first || {}

      options[:display_name] = array.grep(String).first || default_name
      options[:field_class] = array.grep(Class).first || default_field_class

      options
    end
  end
end

class Raw < Packet
  name "Raw Data"
end

