
class BitStruct
  class FloatField < Field
    def get(instance)
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
      
      instance[byte_range].unpack(ctl).first
    end
    
    def set(instance, value)
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

      instance.ensure_length(last_byte)
      instance[byte_range] = [value].pack(ctl)
    end
    
    def empty!(instance)
      set(instance, 0.0)
    end
  end
  
  class << self
    def float(name, length, *rest)
      opts = parse_options(rest, name, FloatField)
      add_field(name, length, opts)
    end
  end
end
