#!/usr/bin/env ruby
require File.join(File.dirname(__FILE__), 'options')
require File.join(File.dirname(__FILE__), 'probe')
require File.join(File.dirname(__FILE__), 'fingerprint_diagram')
require File.join(File.dirname(__FILE__), 'lib/dot11/dot11')

module Baffle
  def self.run(args)
    p "running baffle!"
    @options = Baffle::Options.parse(args)
    p "parsed arguments"

    Baffle::Probes.each do |probe|
      vector = probe.run(@options)
      puts "running probe #{probe.name}"
      if @options.fpdiagram
        File.open(@options.fpdiagram + probe.name + '.svg', 'w+') do |out|
          out.write Baffle.fingerprint_diagram(vector).to_s
        end 
      end
      
      puts "#{probe.name} hypothesizes #{probe.hypothesize(vector).inspect}"
      puts "from vector: #{vector.inspect}"
    end
    p "done!!!"
  end
end

Baffle.run(ARGV) if __FILE__ == $0
