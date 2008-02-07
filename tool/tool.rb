#!/usr/bin/env ruby
require 'ostruct'
require 'matrix'

require File.join(File.dirname(__FILE__), "options")
require File.join(File.dirname(__FILE__), "probe")
require File.join(File.dirname(__FILE__), "dot11")

options = Baffle::Options.parse(ARGV)

# TODO: Should try to get bssid's if we only have essid.

@classifications = []

Baffle::Probes.each do |probe|
  p = probe.new

  # TODO: Setup capture to file

  p.inject(options)
  
  # TODO: Stop capture to file
  # TODO: Read packets from capture

  packets = []

  40.times do
    packets << OpenStruct.new(:flags => rand(255))
  end
  
  mapping = p.capture(packets)

  # TODO: This is not how a vector should be constructed.
  vector = Vector.elements((1..255).map { |key| mapping[key] })
    
  @classifications << p.classify(vector)
end

p @classifications

