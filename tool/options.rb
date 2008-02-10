require 'optparse'

module Baffle
  class Options
    def self.parse(args)
      options = {}

      opts = OptionParser.new do |opts|
        opts.program_name = "tool.rb"
        opts.version      = "0.1"
        opts.release      = "a"
      
        opts.banner = "Usage: #{opts.program_name} [options] ESSID|BSSID"

        opts.separator("")
        opts.separator("Fingerprinting options:")
        opts.on("-i INTERFACE", "--interface INTERFACE", "The INTERFACE to use for both injection and capture") { |interface| options[:interface] = interface }
        opts.on("-j INTERFACE", "--inject INTERFACE", "The INTERFACE to use for injection") { |interface| options[:inject] = interface }
        opts.on("-c INTERFACE", "--capture INTERFACE", "The INTERFACE to use for capture") { |interface| options[:capture] = interface }
        opts.on("-d DRIVER", "--driver DRIVER", "The driver used for injection") { |driver| options[:driver] = driver }
        opts.separator("")
        opts.separator("Training options:")
        opts.on("-t", "--train", "Train baffle with a new device fingerprint") { options[:train] = true }

        opts.separator("")
        opts.separator("Common options:")
        opts.on("-v", "--verbose", "More detailed output") { options[:verbose] = true }
        opts.on("-?", "--help", "Show this message") { puts opts.help; exit }
        opts.on("--version", "Print the version") { puts opts.ver; exit }
      end
    
      value = opts.parse!(args).first

      if value =~ /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/
        options[:bssid] = value
      else
        options[:essid] = value
      end
    
      unless options[:bssid] || options[:essid]
        puts opts.help 
        exit
      end
    
      options
    end
  end
end