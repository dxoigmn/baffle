class Packet
  class UnsignedField < Field
    
    def get(instance, buffer)
      offset_byte = offset(instance) / 8
      offset_bit = offset(instance) % 8
      
      length_bit = offset_bit + length(instance)
      length_byte = (length_bit / 8.0).ceil
            
      last_byte = offset_byte + length_byte - 1

      if offset_byte + length_byte > buffer.length
        return options[:default] || options["default"] || nil
      end
      
      divisor = options[:fixed] || options["fixed"]
      divisor_f = divisor && divisor.to_f
      
      endian = (options[:endian] || options["endian"]).to_s
      case endian
      when "native"
        ctl = length(instance) <= 16 ? "S" : "L"
      when "little"
        ctl = length(instance) <= 16 ? "v" : "V"
      when "network", "big", ""
        ctl = length(instance) <= 16 ? "n" : "N"
      else
        raise ArgumentError,
          "Unrecognized endian option: #{endian.inspect}"
      end
      
      # This should not be in here
      data_is_big_endian = ([1234].pack(ctl) == [1234].pack(length(instance) <= 16 ? "n" : "N"))
      
      if length_byte == 1
        rest = 8 - length_bit
        mask  = ["0"*offset_bit + "1"*length(instance) + "0"*rest].pack("B8")[0]
        mask2 = ["1"*offset_bit + "0"*length(instance) + "1"*rest].pack("B8")[0]
      
        if divisor
          return ((buffer[offset_byte] & mask) >> rest) / divisor_f
        else
          return (buffer[offset_byte] & mask) >> rest
        end
      elsif offset_bit == 0 and length(instance) % 8 == 0
        field_length = length(instance)
        byte_range = offset_byte..last_byte
        
        case field_length
        when 8
          if divisor
            return buffer[offset_byte] / divisor_f
          else
            return buffer[offset_byte]
          end
        when 16, 32
          if divisor
            return buffer[byte_range].unpack(ctl).first / divisor_f
          else
            return buffer[byte_range].unpack(ctl).first
          end
        else
          reader_helper = proc do |substr|
            bytes = substr.unpack("C*")
            bytes.reverse! unless data_is_big_endian
            bytes.inject do |sum, byte|
              (sum << 8) + byte
            end
          end
          
          writer_helper = proc do |val|
            bytes = []
            while val > 0
              bytes.push val % 256
              val = val >> 8
            end
            if bytes.length < length_byte
              bytes.concat [0] * (length_byte - bytes.length)
            end

            bytes.reverse! if data_is_big_endian
            bytes.pack("C*")
          end    
      
          if divisor
            return reader_helper[buffer[byte_range]] / divisor_f
          else
            return reader_helper[buffer[byte_range]]
          end
        end
      
      elsif length_byte == 2
        byte_range = offset_byte..last_byte
        rest = 16 - length_bit
        
        mask  = ["0"*offset_bit + "1"*length + "0"*rest]
        mask = mask.pack("B16").unpack(ctl).first
        
        mask2 = ["1"*offset_bit + "0"*length + "1"*rest]
        mask2 = mask2.pack("B16").unpack(ctl).first
        
        if divisor
          return ((buffer[byte_range].unpack(ctl).first & mask) >> rest) / divisor_f
        else
          return (buffer[byte_range].unpack(ctl).first & mask) >> rest
        end
      else
        raise "unsupported: #{inspect}"
      end
    end
      
    def set(instance, buffer, value)
      offset_byte = offset(instance) / 8
      offset_bit = offset(instance) % 8
      
      length_bit = offset_bit + length(instance)
      length_byte = (length_bit / 8.0).ceil
      
      last_byte = offset_byte + length_byte - 1
      
      divisor = options[:fixed] || options["fixed"]
      divisor_f = divisor && divisor.to_f
      
      endian = (options[:endian] || options["endian"]).to_s
      case endian
      when "native"
        ctl = length(instance) <= 16 ? "S" : "L"
      when "little"
        ctl = length(instance) <= 16 ? "v" : "V"
      when "network", "big", ""
        ctl = length(instance) <= 16 ? "n" : "N"
      else
        raise ArgumentError,
          "Unrecognized endian option: #{endian.inspect}"
      end
            
      # This should not be in here
      data_is_big_endian = ([1234].pack(ctl) == [1234].pack(length(instance) <= 16 ? "n" : "N"))
      
      if length_byte == 1
        rest = 8 - length_bit
        mask  = ["0"*offset_bit + "1"*length(instance) + "0"*rest].pack("B8")[0]
        mask2 = ["1"*offset_bit + "0"*length(instance) + "1"*rest].pack("B8")[0]
      
        if divisor
          value = (value * divisor).round
          buffer[offset_byte] = (buffer[offset_byte] & mask2) | ((value << rest) & mask)
        else
          buffer[offset_byte] = (buffer[offset_byte] & mask2) | ((value << rest) & mask)
        end
      elsif offset_bit == 0 and length(instance) % 8 == 0
        field_length = length(instance)
        byte_range = offset_byte..last_byte
        
        case field_length
        when 8
          if divisor
            value = (value * divisor).round
            buffer[offset_byte] = value
          else
            buffer[offset_byte] = value
          end
        when 16, 32
          if divisor
            value = (value * divisor).round
            buffer[byte_range] = [value].pack(ctl)
          else
            buffer[byte_range] = [value].pack(ctl)
          end
        else
          reader_helper = proc do |substr|
            bytes = substr.unpack("C*")
            bytes.reverse! unless data_is_big_endian
            bytes.inject do |sum, byte|
              (sum << 8) + byte
            end
          end
          
          writer_helper = proc do |val|
            bytes = []
            while val > 0
              bytes.push val % 256
              val = val >> 8
            end
            if bytes.length < length_byte
              bytes.concat [0] * (length_byte - bytes.length)
            end

            bytes.reverse! if data_is_big_endian
            bytes.pack("C*")
          end    
      
          if divisor
            buffer[byte_range] = writer_helper[(value * divisor).round]
          else
            buffer[byte_range] = writer_helper[value]
          end
        end
      
      elsif length_byte == 2
        byte_range = offset_byte..last_byte
        rest = 16 - length_bit
        
        mask  = ["0"*offset_bit + "1"*length + "0"*rest]
        mask = mask.pack("B16").unpack(ctl).first
        
        mask2 = ["1"*offset_bit + "0"*length + "1"*rest]
        mask2 = mask2.pack("B16").unpack(ctl).first
        
        if divisor
          value = (value * divisor).round
          x = (buffer[byte_range].unpack(ctl).first & mask2) | ((value << rest) & mask)
          buffer[byte_range] = [x].pack(ctl)
          
        else
          x = (buffer[byte_range].unpack(ctl).first & mask2) | ((value << rest) & mask)
          buffer[byte_range] = [x].pack(ctl)
        end
      else
        raise "unsupported: #{inspect}"
      end
    end
    
    # TODO: clean me up
    def to_filter(instance)
      len = length(instance)
      off = offset(instance)
      
      if len > 32
        raise "to_filter in unsigned_field not yet implemented for len > 4"
      else
        mask = nil
        
        if off % 8 == 0
          b_off = off / 8
        else
          b_off = (off / 8.0).floor 
        end
        
        if len % 8 == 0
          b_len = len / 8
        else
          b_len = (len / 8.0).ceil
          mask = 2 ** (off + len) - 2 ** (off)
          
        end

        if mask
          "(wlan[#{b_off}:#{b_len}] & 0x#{mask.to_s(16)}) = #{instance.send(self.name)}"
        else
          "wlan[#{b_off}:#{b_len}] = #{instance.send(self.name)}"
        end
        
      end
    end
  end
  
  class << self
    def unsigned(name, length, *rest)
      options = parse_options(rest, name, UnsignedField)
      add_field(name, length, options)
    end
  end
end
