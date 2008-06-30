#!/usr/bin/env ruby
require File.join(File.dirname(__FILE__), 'options')
require File.join(File.dirname(__FILE__), 'probe')
require File.join(File.dirname(__FILE__), 'fingerprint_diagram')
require File.join(File.dirname(__FILE__), 'lib/dot11/dot11')

module Baffle
  def self.run(args)
    @options = Baffle::Options.parse(args)

    Baffle::Probes.each do |probe|
      puts "Running probe #{probe.name}"
      vector = probe.run(@options)
     
      unless vector
        warn "Probe was skipped."
        next
      end

      if @options.fpdiagram
        File.open(@options.fpdiagram + probe.name + '.svg', 'w+') do |out|
          out.write Baffle.fingerprint_diagram(vector).to_s
        end 
      end

      if @options.train?
        puts "got vector: #{vector.inspect}"
      else
        puts "#{probe.name} hypothesizes #{probe.hypothesize(vector).inspect}"
        puts "from vector: #{vector.inspect}"
      end
    end
  end
end

Baffle.run(ARGV) if __FILE__ == $0
