#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "options")
require File.join(File.dirname(__FILE__), "probe")

options = Baffle::Options.parse(ARGV)

Baffle::Probes.each do |probe|
  # TODO: Instantiate probe, and run test against specified device.
end

