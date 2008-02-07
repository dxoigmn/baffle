#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "options")
require File.join(File.dirname(__FILE__), "probe")
require File.join(File.dirname(__FILE__), "dot11")

options = Baffle::Options.parse(ARGV)

# TODO: Should try to get bssid's if we only have essid.

Baffle::Probes.each do |probe|
  p = probe.new
  p.run(options)
  # TODO: Instantiate probe, and run test against specified device.
end

