$PREVENT_INAPPLICABLE_FIELDS = false

class BitStruct < String
  undef type

  class Field
    attr_reader :parent
    attr_reader :name
    attr_reader :options
    attr_reader :display_name
    attr_reader :default
    attr_reader :format
  
    def initialize(parent, name, options)
      @parent, @name = parent, name

      @length = options[:length]
      @applicable_proc = options[:applicable]
      @options = options
    end
    
    def offset(instance)
      field_index = @parent.field_hash[name]
      
      # Check me later
      return 0 if field_index == 0
      
      # Find the last applicable field
      while (!(previous_field = @parent.fields[field_index -= 1]).applicable?(instance)) 
      end
      
      previous_field.offset(instance) + previous_field.length(instance)
    end
    
    def get(instance)
      0
    end

    def set(instance, value)

    end
    
    def emtpy!(instance)
      
    end
    
    def length(instance)
      @length
    end
    alias size length
    
    def inspectable?
      true
    end
    
    def applicable?(instance)
      if @applicable_proc
        @applicable_proc.call(instance)
      else
        true
      end
    end
  end
  
  def get_field_value(name)
    field = self.class.field(name)
    
    if field.applicable?(self)
      field.get(self)
    else
      nil
    end
  end
   
  def set_field_value(name, value)
    field = self.class.field(name)
    
    if field.applicable?(self)
      field.set(self, value)
    end
  end
  
  def ensure_length(length)
    if length > self.to_s.length
      self.concat("\0" * (length - self.to_s.length))
    end
  end
  
  def method_missing(name, *args)
    field_name = name.id2name.sub(/=$/, '').intern
    
    if self.class.has_field?(field_name)
      raise "The requested field #{field_name.id2name} is not applicable to #{self.inspect}" if $PREVENT_INAPPLICABLE_FIELDS && !self.class.field(field_name).applicable?(self)
      
      if field_name == name
        get_field_value(field_name)
      else
        set_field_value(field_name, args[0])
      end
    else
      raise NoMethodError.new("undefined method #{name.id2name} on #{self.class.name}")
    end
  end
  
  def initialize(*options)
    if options.size == 1 and options[0].kind_of?(String)
      super(options[0])
    else
      self.class.fields.each do |field|
        if field.applicable?(self)
          field.empty!(self)
        end
      end
    end
  end
  
  class << self
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

    def add_field(name, length, opts = {})
      field_class = opts[:field_class]
      
      opts[:length] = length
      
      field = field_class.new(self, name, opts)
      
      field_hash[name] = fields.size
      fields << field

      field
    end

    def parse_options(array, default_name, default_field_class)
      opts = array.grep(Hash).first || {}
      #opts = default_options.merge(opts)

      opts[:display_name] = array.grep(String).first || default_name
      opts[:field_class] = array.grep(Class).first || default_field_class

      opts
    end
  end
end

require 'char_field'
require 'float_field'
require 'unsigned_field'
require 'nested_field'
require 'octet_field'
require 'hex_octet_field'
require 'enum_field'
require 'flags_field'
require 'pad_field'
require 'signed_field'
require 'text_field'

