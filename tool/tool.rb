#!/usr/bin/env ruby
require File.join(File.dirname(__FILE__), "options")
require File.join(File.dirname(__FILE__), "probe")
require File.join(File.dirname(__FILE__), "dot11")
require 'ostruct'

module Baffle
  def self.run(args)
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

      rand(10).times do
        packets << OpenStruct.new(:flags => rand(10))
      end
  
      @classifications << p.classify(p.capture(packets))
    end

    p @classifications

    # TODO: Aggregrate classifications
  end
end

Baffle.run(ARGV)
