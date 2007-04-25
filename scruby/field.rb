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
class StrField<Field

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
class MACField<Field

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

# One day, this will be computed automatically :)
FIELD_LIST = [StrField, ByteField, XByteField, ShortField,
              XShortField, LongField, LELongField, HostOrderLongField,
              IntField, IPField, MACField]
end
