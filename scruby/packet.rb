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

class Packet

  attr_accessor :layers_list

# Constructor
def initialize(arg1, arg2)

  # List of layers
  @layers_list = []

  # There are two cases for the arguments:
  # 1) arg1 is a string to dissect and arg2 the wanted dissector
  # 2) arg1 and arg2 are layers to bind together.

  # First case
  if arg1.is_a?(String) and arg2.is_a?(String)

    # Getting the dissector from its string
    index = DISSECTOR_LIST_S.index(arg2)

    # These variables are used in the loop below.
    dissector = DISSECTOR_LIST[index]
    remain = arg1

    begin
      # Creating a new layer and adding it to the current packet
      new_layer = dissector.__send__('new', remain)
      @layers_list.push(new_layer)

      # Preparing the remaining string for the next loop
      remain = new_layer.tobedecoded
      
      # If the upper layer was guessed by the new layer
      if not new_layer.guesses[0].nil?
        # In this version, only the first guess is considered.
        dissector = new_layer.guesses[0]

      # Else, it is considered as raw data.
      else
        dissector = Raw
      end

    end until remain.length == 0

  # Second case
  else
    @layers_list = [arg1, arg2].flatten
   end
end

def /(upper)
  return Packet./(self, upper)
end

# Add a layer/packet/some raw data on top of a layer/packet/some raw data
def Packet./(lower, upper)

  # Transforms a string into a Raw layer. This allows
  # "IP()/"GET HTTP 1.0\r\n\r\n".
  lower = Raw.new(:load=>lower) if lower.is_a?(String)
  upper = Raw.new(:load=>upper) if upper.is_a?(String)

  # Packet/Layer
  if lower.instance_of?(Packet) and not upper.instance_of?(Packet)
    return Packet.new(lower.layers_list, upper)

  # Packet/Packet
  elsif lower.instance_of?(Packet) and upper.instance_of?(Packet)
    return Packet.new(lower.layers_list, upper.layers_list)

  # Layer/Packet
  elsif not lower.instance_of?(Packet) and upper.instance_of?(Packet)
    return Packet.new(lower, upper.layers_list)

  # Layer/Layer
  elsif not lower.instance_of?(Packet) and not upper.instance_of?(Packet)
    return Packet.new(lower, upper)
  end
  
end

# Converts an object to a string
def to_s
  
  out = ''
  
  @layers_list.each do |layer|
    out += layer.to_s
  end
  
  return out
end

# Displays the packet with more details than tostring
def show

  out = ''
  
  @layers_list.each do |layer|
    out += layer.show + "\n"
  end
  
  return out

end

# Returns the string ready to be sent on the wire
def tonet
  out = ''
  payload = ''
  underlayer = nil
  
  @layers_list.each do |layer|
    # Only some protocols need to be aware of upper layers
    if $aware_proto.include?(layer.protocol)
      payload = self.get_payload(layer)
    end

    layer.pre_send(underlayer, payload)
    
    out += layer.tonet()
    underlayer = layer
    payload = ''
  end

  return out
end

# Returns the payload of a layer
def get_payload(layer_arg = self)

  payload = ''
  concat = false

  @layers_list.each do |layer|
    if layer == layer_arg
      concat = true
    elsif concat == true
      payload += layer.tonet()
    end

  end

  return payload
end

end
end
