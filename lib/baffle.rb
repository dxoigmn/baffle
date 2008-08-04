#!/usr/bin/env ruby
require 'rubygems'
require 'dot11'

require File.expand_path(File.join(File.dirname(__FILE__), 'baffle', 'options'))
require File.expand_path(File.join(File.dirname(__FILE__), 'baffle', 'probe'))
require File.expand_path(File.join(File.dirname(__FILE__), 'baffle', 'fingerprint_diagram'))

module Baffle
  def self.run(args)
    options = Baffle::Options.parse(args)
    
    options
    
    if options.gui?
      require File.expand_path(File.join(File.dirname(__FILE__), 'baffle', 'gui'))
      
      Gui.run(options)
    else
      scan(options)
    end
  end
  
  def self.scan(options)
    hypotheses = {}
    
    Baffle::Probes.each do |probe|
      puts "Running probe #{probe.name}"
      vector = probe.run(options)
      
      unless vector
        warn "Probe was skipped."
        next
      end
      
      if options.fpdiagram
        File.open("#{options.fpdiagram}#{probe.name}.svg", 'w+') do |out|
          out.write Baffle.fingerprint_diagram(vector).to_s
        end
      end
      
      puts "Vector: #{vector.inspect}"
      
      hypotheses[probe.name] = probe.hypothesize(vector)
      
      unless options.train?
        puts "#{probe.name} hypothesizes: #{probe.hypothesize(vector)}"
      end
    end
    
    hypotheses
  end
end
