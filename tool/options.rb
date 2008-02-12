require 'optparse'

module Baffle
  class Options < Hash
    attr_accessor :inject
    attr_accessor :capture
    attr_accessor :driver
    attr_accessor :channel
    attr_accessor :train
    attr_accessor :verbose

    def initialize
      @inject   = 'ath0'
      @capture  = 'ath0'
      @driver   = 'madwifing'
      @channel  = 11
      @train    = false
      @verbose  = false
    end
    
    def train?; self.train; end
    def verbose?; self.verbose; end
    def interface=(value); self.inject = value; self.capture = value; end
    
    def self.parse(args)
      options = Options.new

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
        opts.on("-c CHANNEL", "--channel CHANNEL", "The channel to listen on") { |channel| options[:channel] = channel }

        opts.separator("")
        opts.separator("Output options:")
        opts.on("-f SVGFILE", "--fpdiagram SVGFILE", "Write a fingerprint diagram to SVGFILE") { |svgfile| options[:fpdiagram] = svgfile }
        opts.on("-p SVGPREFIX", "--plot SVGPREFIX", "Write a plot file for each probe used, using SVGPREFIX") { |svgfile| options[:plot_prefix] = svgfile }
        
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
