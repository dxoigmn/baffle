#!/usr/bin/env ruby
require File.join(File.dirname(__FILE__), 'options')
require File.join(File.dirname(__FILE__), 'probe')
require File.join(File.dirname(__FILE__), 'fingerprint_diagram')
require File.join(File.dirname(__FILE__), 'lib/dot11/dot11')

module Baffle

  def self.run(args)
    @options = Baffle::Options.parse(ARGV)
    Baffle::Probes.each do |probe|
      vector = probe.run
      
      if @options.fpdiagram
        File.open(@options.fpdiagram + probe.name + '.svg', 'w+') do |out|
          out.write Baffle.fingerprint_diagram(vector).to_s
        end 
      end
      
      probe.hypothesize(vector)
    end
  end
end

Baffle.run(ARGV)
