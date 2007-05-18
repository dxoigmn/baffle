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
      @applicable_proc = options[:applicable]
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
      @length || 0
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
    
end

require 'fields/fields'