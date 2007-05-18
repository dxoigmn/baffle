require 'field'

$PREVENT_INAPPLICABLE_FIELDS = false

class Packet
  undef type
  
  def length
    last_field = self.class.fields[-1]
    
    ((last_field.offset(self) + last_field.length(self)) / 8).ceil
  end
  alias size length
  
  def data
    construct
  end
  
  def data=(string)
    dissect(string)
  end
  
  def initialize(*parameters)
    if parameters.length == 1 and parameters[0].kind_of?(String)
      data = parameters[0]
    end
  end
  
  def /(other)
    if self.class.nested_field
      duplicate = dup
      duplicate.send(:set_field_value, self.class.nested_field.name, other)
      
      duplicate
    else
      raise "Packet cannot contain a payload"
    end
  end
  
  private
  
  def construct
    buffer = "\0" * length
    
    self.class.fields.each do |field|
      name = field.name
      
      value = get_field_value(name)
      field.set(self, buffer, value) if value
    end
    
    buffer
  end
  
  def dissect(string)
    self.class.fields.each do |field|
      name = field[name]

      value = field.get(self, buffer)
      
      set_field_value(name, value)
    end    
  end
 
  def get_field_value(field_name)
    (@field_values ||= {})[field_name]
  end
  
  def set_field_value(field_name, value)
    (@field_values ||= {})[field_name] = value
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

