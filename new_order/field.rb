class FilterExpression
  attr_accessor :operator
  attr_accessor :left, :right
  
  def initialize(operator, left, right)
    @operator = operator
    @left = left
    @right = right
  end
  
  def evaluate(instance)
    if @left.kind_of?(Symbol)
      left_value = instance.send(@left)
    elsif @left.kind_of?(FilterExpression)
      left_value = @left.evaluate(instance)
    else
      left_value = @left
    end
    
    if @right.kind_of?(Symbol)
      right_value = instance.send(@right)
    elsif @right.kind_of?(FilterExpression)
      right_value = @right.evaluate(instance)
    else
      right_value = @right
    end
    
    left_value.send(@operator, right_value)
  end
end

class Symbol
  [:&, :|].each do |operator|
    define_method operator do |other|
      FilterExpression.new(operator, self, other)
    end
  end
end

class Packet
  class Field
    attr_reader :parent
    attr_reader :name
    attr_reader :options
    attr_reader :display_name
    attr_reader :default
    attr_reader :format
  
    def initialize(parent, name, options)
      @parent, @name = parent, name

      @options = options
      @length = options[:length]
      @display_name = options[:display_name]
      @applicable = options[:applicable]
      @format = options[:format]
    end
    
    def offset(instance)
      field_index = @parent.field_hash[name]
      
      return 0 if field_index == 0
      
      # Find the last applicable field
      while (!(previous_field = @parent.fields[field_index -= 1]).applicable?(instance));  end
      
      previous_field.offset(instance) + previous_field.length(instance)
    end
    
    def get(instance, buffer)
      nil
    end

    def set(instance, buffer, value)
      nil
    end
    
    def length(instance)
      if @length.kind_of?(Proc)
        @length[instance]
      else
        @length || 0
      end
    end
    alias size length
    
    def inspectable?
      true
    end
    
    def applicable?(instance)      
      if @applicable
        is_applicable?(instance, @applicable)
      else
        true
      end
    end
    
    def is_applicable?(instance, applicable)
      if applicable.kind_of?(Array)
        condition, pass, fail = applicable
        
        if is_applicable?(instance, condition)
          is_applicable?(instance, pass)
        else
          is_applicable?(instance, fail)
        end
      elsif applicable.kind_of?(Hash)
        passed = true
        
        applicable.each_key do |key|
          if key.kind_of?(FilterExpression)
            value = key.evaluate(instance)
          else
            value = instance.send(key)
          end
          
          if applicable[key].kind_of?(Numeric)
            passed &= (applicable[key] == value)              
          elsif applicable[key].kind_of?(Array) || applicable[key].kind_of?(Range)
            passed &= (applicable[key].include?(value))
          end
          
        end
        
        passed        
      elsif applicable.kind_of?(TrueClass) || applicable.kind_of?(FalseClass)
        applicable
      end
    end
  end
    
end

require 'fields/fields'
