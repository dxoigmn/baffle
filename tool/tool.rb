#!/usr/bin/env ruby
require File.join(File.dirname(__FILE__), 'options')
require File.join(File.dirname(__FILE__), 'probe')
require File.join(File.dirname(__FILE__), 'dot11')

module Baffle
  def self.run(args)
    @options = Baffle::Options.parse(ARGV)
    
    Baffle::Probes.each do |probe|
      p probe
    end
  end
end

Baffle.run(ARGV)
