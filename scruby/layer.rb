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

class Layer

  attr_accessor :protocol
  attr_accessor :fields_desc
  attr_accessor :tobedecoded
  attr_accessor :guesses

# Constructor
def initialize(args = {})

  @protocol = 'Generic layer'

  # Array containing the protocol fields (see dissectors.rb)
  @fields_desc = []

  # Part of the string that couldn't be decoded, to be passed to the
  # upper layer
  @tobedecoded = nil

  # Guesses for the upper layer
  @guesses = []

  # Cleaning arguments
  if not args.is_a?(Hash) and not args.is_a?(String)
    args = {}
  end
  
  # Constructing the layer
  init()

  # The default values are applied.
  @fields_desc.each do |field|
    self.instance_variable_set("@#{field.name}", field.default_value)
  end

  # If a single string argument is passed (e.g. "Ether('string')")
  if args.is_a?(String)

    # The values for this layer are retrieved from the beginning of
    # the string. build_from_string returns the end of the string,
    # that couldn't be decoded.
    @tobedecoded = build_from_string(args)

    # If there is something left to be decoded
    if @tobedecoded.length > 0

      # layer_bounds is run throught to try to guess the upper layer.
      # There can be several answers (array @guesses).
      myclass = self.class.to_s.split('::')[1]  
      proto_array = $layer_bounds.has_key?(myclass) ? $layer_bounds[myclass] : []

      proto_array.each do |triplet|
        # Value from the layer_bounds triplet and the real one are compared.
        # e.g. for ['type', ETHERTYPE_IPv4, IP], if the field "type"
        # in the current Ethernet layer is 0x800, then the upper layer
        # is (may be) IP.
        if self.instance_variable_get("@#{triplet[0]}") == triplet[1]
          # Adding this possibility
          @guesses.push(triplet[2])
          break
        end
      end
    end

  else
    # At this point, args is a hash.
    # Adding the field values, overwriting the default values if the
    # user specified some.
    # There is no verification of the validity of the arguments passed;
    # that is to say something like "IP(:foo=>'bar')" will not
    # display any error (the argument will just be ignored).
    
    # Converting symbols to strings
    args.each_key do |symbol|
      args[symbol.to_s] = args[symbol]
    end

    @fields_desc.each do |field|
      # Setting the variable value
      value = args.has_key?(field.name) ? args[field.name] : field.default_value
      self.instance_variable_set("@#{field.name}", value)
    end
  end
end

# Layer initialization. This function have to be redefined by subclasses.
def init
end

# Redefines the "/" operator (allows "p=IP()/TCP()").
def /(upper)
  return Packet./(self, upper)
end

# Converts an object to a string
def to_s
  
  # Name of the protocol
  out = "<#{@protocol}"
  
  # Only the fields whose values are not the default ones will be displayed.
  @fields_desc.each do |field|
    if self.instance_variable_get("@#{field.name}") != field.default_value
      out += " #{field.name}="
      out += field.tohuman(self.instance_variable_get("@#{field.name}"))
    end
  end
  
  return out += ' |>'
end

# Displays the packet with more details than to_s
def show
  
  # Name of the protocol
  out = "###[ #{@protocol} ]###"
  
  # List of fields in this layer
  @fields_desc.each do |field|
    out += "\n#{field.name} = " + field.tohuman(self.instance_variable_get("@#{field.name}"))
  end

  return out
end

# Returns the string ready to be sent on the wire
def tonet()
  out = ''

  @fields_desc.each do |field|
    out += field.tonet(self.instance_variable_get("@#{field.name}"))
  end

  return out
end

# Finishes the packet just before sending it (checksum, etc).
# This function may be redefined by subclasses.
def pre_send(underlayer = nil, payload = nil)
end

# Retrieves field values from a string and returns what was not decoded
def build_from_string(string)

  remain = ''
  
  @fields_desc.each do |field|
    part = string.unpack(field.format + 'a*');

    # Returning if nothing could be unpacked
    return '' if part[-2].nil? or part[-2] == ''

    # 'remain' is the last elements of the array (unpacking 'a*'),
    # with this command, part doesn't contain 'remain' anymore.
    remain = part.pop

    # Updating the field value
    self.instance_variable_set("@#{field.name}", field.fromnet(part))
  
    # Deleting the part of the string that was processed
    string = remain
  end

  return remain
end

# Computes the checksum of a string
def Layer.checksum(string)

  s = 0
  i = 0

  # Adding a null character if needed
  if string.length % 2 != 0
    string += 0.chr
  end

  while i < (string.length)/2
    s += string[2*i, 2].unpack('n')[0]
    i += 1
  end
  
  s = (s >> 16) + (s & 0xffff)
  s = ~((s >> 16) + s) & 0xffff

  return s
end

end
end
