class Packet
  class FloatField < Field
    def get(instance, buffer)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte
      
      endian = (options[:endian] || options["endian"]).to_s
      case endian
      when "native"
        ctl = case length(instance)
          when 32; "f"
          when 64; "d"
        end
      when "little"
        ctl = case length(instance)
          when 32; "e"
          when 64; "E"
        end
      when "network", "big", ""
        ctl = case length(instance)
          when 32; "g"
          when 64; "G"
        end
      else
        raise ArgumentError,
          "Unrecognized endian option: #{endian.inspect}"
      end
      
      buffer[byte_range].unpack(ctl).first
    end
    
    def set(instance, buffer, value)
      offset_byte = offset(instance) / 8
      length_byte = length(instance) / 8
      last_byte = offset_byte + length_byte - 1
      byte_range = offset_byte..last_byte

      endian = (options[:endian] || options["endian"]).to_s
      case endian
      when "native"
        ctl = case length(instance)
          when 32; "f"
          when 64; "d"
        end
      when "little"
        ctl = case length(instance)
          when 32; "e"
          when 64; "E"
        end
      when "network", "big", ""
        ctl = case length(instance)
          when 32; "g"
          when 64; "G"
        end
      else
        raise ArgumentError,
          "Unrecognized endian option: #{endian.inspect}"
      end

      buffer[byte_range] = [value].pack(ctl)
    end
  end
  
  class << self
    def float(name, length, *rest)
      options = parse_options(rest, name, FloatField)
      add_field(name, length, options)
    end
  end
end
