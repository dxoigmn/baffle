#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby
  class Field

    attr_accessor :name
    attr_accessor :default_value
    attr_accessor :format

    # Constructor
    def initialize(name, default_value)
      @name = name
      @default_value = default_value
      @format = ''

      self.init()
    end

    # Field initialization. This function have to be redefined by subclasses.
    def init
    end

    # Converts from network to internal encoding
    # e.g for IP->{dst}: number 2130706433 -> string "127.0.0.1" (2130706433 = 127*2^24 + 1*2^0)
    def fromnet(value)
      return value[0]
    end

    # Converts from internal encoding to network
    # e.g. for IP->{dst}: string "127.0.0.1"-> number 2130706433
    def tonet(value)
      return [value].pack(@format)
    end

    # Converts from internal encoding to human display
    # e.g. displays "0xDEADBEEF" for checksums
    def tohuman(value)
      return value.to_s
    end

  end

  # Field for a string
  class StrField < Field

    def init
      @format = 'A*'
    end

    def tonet(value)
      return value.to_s
    end

    def tohuman(value)
      return value.to_s.inspect
    end

  end

  # Field for one byte
  class ByteField<Field

    def init
      @format = 'C'
    end

  end

  # Same as ByteField, displayed in hexadecimal form
  class XByteField<ByteField

    def tohuman(value)
      return sprintf('0x%x', value)
    end

  end

  # Field for one short (big endian/network order)
  class ShortField<Field

    def init
      @format = 'n'
    end

  end

  class LEShortField < Field
    def init
      @format = 'v'
    end
  end

  # Same as ShortField, displayed in hexadecimal form
  class XShortField<ShortField

    def tohuman(value)
      return sprintf('0x%x', value)
    end

  end

  # Field for one long (big endian/network order)
  class LongField<Field

    def init
      @format = 'N'
    end

  end

  # Field for one long (little endian order)
  class LELongField<LongField

    def init
      @format = 'V'
    end

  end

  # Field for one long (host order)
  class HostOrderLongField<LongField

    def init
      @format = 'L_'
    end

  end

  # Field for one integer
  class IntField<Field

    def init
      @format = 'I'
    end

  end

  # Field for an IP address
  class IPField<Field

    def init
      @format = 'N'
      @ip_addr = nil
    end

    # Ruby equivalent to inet_aton. It takes a hostname or an IP as an argument.
    def inet_aton(name)
      ip = Socket.getaddrinfo(name, nil)[0][3]
      return [IPAddr.new(ip).to_i].pack(@format)
    end

    def tonet(value)

      # Getting the IP address from the server name if needed
      if @ip_addr.nil?
        @ip_addr = inet_aton(value)
      end

      return @ip_addr
    end

    def fromnet(value_array)
      return IPAddr.new(value_array[0], Socket::AF_INET).to_s
    end

  end

  # Field for an MAC address
  class MACField < Field

    def init
      @format = 'H2H2H2H2H2H2'
    end

    def tonet(value)
      # value can be empty (e.g. loopback device)
      if value.nil?
        value = '00:00:00:00:00:00'
      end

      # Get the bytes in an string array
      bytes = value.split(':')

      return bytes.pack(@format)
    end

    def fromnet(value)
      # value is an array containing 6 bytes
      return value.join(':')
    end

  end
  
  class BitField < Field
    attr_accessor :size
    
    def initialize(name, default, size)
      super(name, default)
      self.size = size
    end

    def addfield(pkt, s, val)
      if val.nil?
        val = 0
      end

      if s.kind_of?(Array)
        s, bitsdone, v = s
      else
        bitsdone = 0
        v = 0
      end

      v <<= self.size
      v |= val & ((1 << self.size) - 1)
      bitsdone += self.size
      while bitsdone >= 8
        bitsdone -= 8
        s = s + [v >> bitsdone].pack("C")
        v &= (1<<bitsdone) - 1
      end

      if bitsdone
        return s,bitsdone,v
      else
        return s
      end
    end

    def getfield(pkt, s)
      if s.kind_of?(Array)
        s,bn = s
      else
        bn = 0
      end

      # we don't want to process all the string
      nb_bytes = (self.size+bn-1)/8 + 1
      w = s[0, nb_bytes]

      # split the substring byte by byte
      bytes = w.unpack('%dC' % nb_bytes)

      b = 0
      nb_bytes.times do |c|
        b |= long(bytes[c]) << (nb_bytes-c-1)*8
      end

      # get rid of high order bits
      b &= (1 << (nb_bytes*8-bn)) - 1

      # remove low order bits
      b = b >> (nb_bytes*8 - self.size - bn)

      bn += self.size
      s = s[bn / 8..-1]
      bn = bn % 8
      if bn
        return [s,bn],b
      else
        return s,b
      end
    end

    def randval
      return RandNum(0,2**self.size-1)
    end
  end

  class FlagsField < BitField
    attr_accessor :multi, :names
    
    def initialize(name, default, size, names)
      super(name, default, size)
      self.multi = names.kind_of?(Array)
      if self.multi
        self.names = names.map {|x| [x]}
      else
        self.names = names
      end
    end

    def any2i(pkt, x)
      if x.kind_of?(String)
        if self.multi
          x = x.split("+").map {|y| [y]}
        end

        y = 0
        x.each do |i| #for i in x
          y |= 1 << self.names.index(i)
        end

        x = y
      end
      return x
    end

    def i2repr(pkt, x)
      if self.multi
        r = []
      else
        r = ""
      end

      i=0
      while x != 0
        if x & 1
          r += self.names[i]
        end
        i += 1
        x >>= 1
      end

      if self.multi
        r = r.join('+')
      end

      return r
    end
  end

  # One day, this will be computed automatically :)
  FIELD_LIST = [StrField, ByteField, XByteField, ShortField, LEShortField,
    XShortField, LongField, LELongField, HostOrderLongField,
    IntField, IPField, MACField, BitField, FlagsField]
end
