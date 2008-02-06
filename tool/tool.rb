#!/usr/bin/env ruby

require 'rubygems'
require 'choice'

BAFFLE_VERSION = "0.1a"

def parse_options
  Choice.options do
    header ''
    header 'Fingerprinting options:'
  
    option :mac do
      short '-m'
      long '--mac=MAC'
      desc 'The MAC address of the device to probe'
    end
  
    option :essid do
      short '-e'
      long '--essid=ESSID'
      desc 'The ESSID of the network to probe'
    end
  
    option :interface do
      short '-i'
      long '--interface'
      desc 'The interface to use for both injection and capture'
    end
  
    option :inject_interface do
      short '-j'
      long '--inject'
      desc 'The interface to use for injection'
    end
  
    option :capture_interface do
      short '-c'
      long '--capture'
      desc 'The interface to use for capture'
    end
  
    separator ''
    separator 'Training options'
  
    option :train do
      short '-t'
      long '--train'
      desc "Train baffle with a new device fingerprint"
      default false
    end
  
    separator ''
    separator 'Common options: '
  
    option :verbose do
      short '-v'
      long '--verbose=LEVEL'
      desc 'Set verbosity level'
      cast Integer
      default 0
    end
  
    option :help do
      short '-?'
      long '--help'
      desc 'Show this message'
      action do 
        Choice.help
        exit
      end
    end
  
    option :version do
      long '--version'
      desc 'Print the version'
      action do
        puts "#{$0} version #{BAFFLE_VERSION}"
        exit
      end
    end
  end
end

p Choice.methods.sort