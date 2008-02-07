#!/usr/bin/env ruby
require 'ostruct'
require File.join(File.dirname(__FILE__), "options")
require File.join(File.dirname(__FILE__), "probe")
require File.join(File.dirname(__FILE__), "dot11")

options = Baffle::Options.parse(ARGV)

# TODO: Should try to get bssid's if we only have essid.

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
  
  vector = p.capture(packets)
  
  # TODO: Classify vector
end

