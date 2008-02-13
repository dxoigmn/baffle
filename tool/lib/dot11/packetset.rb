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
  
    def bitrange_to_filter(offset, size, bitrange, desired, negated = false)
      # TODO: Take bitrange.exclude_end? into account
      mask = ((2 << (bitrange.end - bitrange.begin)) - 1) << bitrange.begin
      
      value = "(ether[#{offset}:#{size}] & #{'%#x' % mask}) >> #{bitrange.begin}"
            
      case desired
      when Range
        "(#{value} >= #{'%#x' % desired.begin} && #{value} #{desired.exclude_end? ? "<" : "<="} #{'%#x' % desired.end})"
      when Array
        # TODO: deal with arrays of ranges
        '(' + desired.map {|d| "#{value} = #{'%#x' % d}"}.join(" || ") + ')'
      when Numeric
        "#{value} #{negated ? '!' : ''}= #{'%#x' % desired}"
      end
    end
    
    def int_to_filter(offset, size, desired, negated = false)
      value = "ether[#{offset}:#{size}]"
      
      case desired
      when Range
        "(#{value} >= #{'%#x' % desired.begin} && #{value} #{desired.exclude_end? ? "<" : "<="} #{'%#x' % desired.end})"
      when Array
        # TODO: deal with arrays of ranges
        desired.map {|d| "#{value} #{negated ? '!' : ''}= #{'%#x' % d}"}.join(" || ")
      when Numeric
        "#{value} #{negated ? '!' : ''}= #{'%#x' % desired}"
      end      
    end
    
    def mac_to_filter(offset, size, desired, negated = false)      
      case desired
      when Range
        raise "Range of MAC addresses in filter not yet implemented"
      when Array
        '(' + desired.map do |d| 
          desired = MACAddress.new(desired) if desired.kind_of?(String)
          first_four = desired[0, 4].pack("CCCC").unpack("N")[0]
          second_two = desired[4, 2].pack("CC").unpack("n")[0]

          "(ether[#{offset}:2] = #{'%#x' % first_four} && ether[#{offset + 4}:2] = #{'%#x' % second_two})"
        end.join(" || ") + ')'
      when Numeric

      when MACAddress, String
        desired = MACAddress.new(desired) if desired.kind_of?(String)
        first_four = desired[0, 4].pack("CCCC").unpack("N")[0]
        second_two = desired[4, 2].pack("CC").unpack("n")[0]
        
        "(ether[#{offset}:2] = #{'%#x' % first_four} && ether[#{offset + 4}:2] = #{'%#x' % second_two})"
      end
    end
    
    def decode_condition(fields, condition)
      case condition
      when Array
        condition.map{|x| decode_condition(fields, x)}.join(" || ")
      when Hash
        condition.map do |key, value|
          # Decode the nasty negation syntax
          negated, value = value.kind_of?(Array) && value.size == 1 ? [true, value[0]] : [false, value]

          field_info = fields.find{|x| key == x[0]}[1]
          
          case field_info[:type]
          when :int
            if field_info.has_key?(:bitrange)
              bitrange_to_filter(field_info[:offset], field_info[:size], field_info[:bitrange], value, negated)
            else
              int_to_filter(field_info[:offset], field_info[:size], value, negated)
            end
          when :mac
            mac_to_filter(field_info[:offset], field_info[:size], value, negated)
          end
        end.join(" && ")
      end
    end
  
    def to_filter      
      fields = @packet_class.fields

      @fields.map do |field|
        '(' + begin
          field_info = fields.find{|x| field.name == x[0]}
          
          next if field_info.nil?
          
          field_info = field_info[1]
          
          # We don't really want to do this
          next if field_info.nil?
                
          if field_info.has_key?(:condition)
            if !field_info[:offset].kind_of?(Numeric)
              field_info[:offset].map do |key, value|
                '(' + begin
                  if key == :else
                    field_info[:offset].keys.reject{|k| k == :else}.map do |k|
                      '!(' + decode_condition(fields, k) + ')'
                    end.join(" && ")
                  else
                    '(' + decode_condition(fields, key) + ') && (' + begin
                      case field_info[:type]
                      when :int
                        if field_info.has_key?(:bitrange)
                          bitrange_to_filter(value, field_info[:size], field_info[:bitrange], field.value)
                        else
                          int_to_filter(value, field_info[:size], field.value)
                        end
                      when :mac
                        mac_to_filter(value, field_info[:size], field.value)
                      end
                    end
                  end
                end + ')'
              end.join(" && ")
            else
              '((' + decode_condition(fields, field_info[:condition]) +') && ('+ case field_info[:type]
              when :int
                if field_info.has_key?(:bitrange)
                  bitrange_to_filter(field_info[:offset], field_info[:size], field_info[:bitrange], field.value)
                else
                  int_to_filter(field_info[:offset], field_info[:size], field.value)
                end
              when :mac
                mac_to_filter(field_info[:offset], field_info[:size], field.value)
              end + '))'
            end
          else
            if !field_info[:offset].kind_of?(Numeric)
              p "moo"
              "can"
            else
              case field_info[:type]
              when :int
                if field_info.has_key?(:bitrange)
                  bitrange_to_filter(field_info[:offset], field_info[:size], field_info[:bitrange], field.value)
                else
                  int_to_filter(field_info[:offset], field_info[:size], field.value)
                end
              when :mac
                mac_to_filter(field_info[:offset], field_info[:size], field.value)
              end
            end
          end
        end + ')'
      end.join(" && ")
    end
  end
end