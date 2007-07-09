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
    fail "Packet #{self.class} cannot contain a nested field." if self.class.nested_field == nil
    
    duplicate = dup
    
    # Find nested field that is not yet filled in.
    unnested = duplicate
    unnested = unnested.nested until unnested.nested.kind_of?(Array) || unnested.nested == nil

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

    if self.class.nested_field.kind_of? ArrayField
      return get_field_value(self.class.nested_field.name) || []
    else
      get_field_value self.class.nested_field.name
    end
  end
  
  def nested=(value)
    fail "Packet #{self.class} cannot contain a nested field." if self.class.nested_field == nil
    
    if self.class.nested_field.kind_of? ArrayField
      
      set_field_value self.class.nested_field.name, (nested << value)
    else
      set_field_value self.class.nested_field.name, value
    end
  end

  def ==(other)
    return false if self.class != other.class
      
    self.class.fields.each do |field|
      self_value = self.send(:get_field_value, field.name) || ""
      other_value = other.send(:get_field_value, field.name) || ""
      
      return false if self_value != other_value
    end
    
    return true
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
      next if !field.applicable?(self)
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
    puts "setting #{field_name} = #{value.inspect}" if field_name == :addr4
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
      raise NoMethodError.new("undefined method #{name.id2name} on #{self.class}")
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

      if field.kind_of? NestedField
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
    
    def build_rule_tree
      simplified_rules = simplify_rules
      
      
    end
    
    def simplify_rules
      simplified_rules = {}
      
      @fields.each do |field|
        if field.has_applicable?
          simplified_rules[field] = simplify_rule(field.applicable)
          p simplified_rules[field]
        end
      end      
      
      simplified_rules
    end
    
    def simplify_rule(rule, explicit = false)
      if rule.kind_of?(Hash)
        simple_rule = []
        base_rule = simple_rule
        
        rule.each_pair do |key, value|
          if value.kind_of?(Array)
            value.each_with_index do |nested_value, index|
              simple_rule[0] = {key => nested_value}
              simple_rule[1] = true
              
              if index < value.size - 1
                simple_rule[2] = []
              else
                simple_rule[2] = false
              end
              
              simple_rule = simple_rule[2] 
            end
          elsif value.kind_of?(Range)  
            raise "Range not implemented in simplify_rule"
          else
            if explicit
              base_rule = [{key => value}, true, false]
            else
              base_rule = {key => value}
            end
          end
        end

        base_rule
      elsif rule.kind_of?(Array)
        simplified_condition = simplify_rule(rule[0])
        
        simplified_true = simplify_rule(rule[1], true)
        simplified_false = simplify_rule(rule[2], true)
                
        [simplified_condition, simplified_true, simplified_false]
      elsif rule == true || rule == false
        rule
      end
    end
  end
end

class Raw < Packet
  name "Raw Data"
end
