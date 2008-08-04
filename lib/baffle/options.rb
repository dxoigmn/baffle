require 'optparse'

module Baffle
  class Options
    attr_accessor :inject
    attr_accessor :capture
    attr_accessor :driver
    attr_accessor :channel
    attr_accessor :train
    attr_accessor :verbose
    attr_accessor :fpdiagram
    attr_accessor :plot_prefix
    attr_accessor :bssid, :essid
    attr_accessor :fast
    attr_accessor :gui

    def initialize
      @inject   = 'ath0'
      @capture  = 'ath0'
      @driver   = 'madwifing'
      @channel  = 11
      @fast     = false
      @train    = false
      @verbose  = false
      @gui      = false
    end
    
    def fast?; @fast == true; end
    def train?; @train == true; end
    def verbose?; @verbose == true; end
    def gui?; @gui == true; end
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
        opts.on("-e ESSID", "--essid ESSID", "The ESSID to send probes and other ESSID-aware to") { |essid| options.essid = essid }
        opts.on("-i INTERFACE", "--interface INTERFACE", "The INTERFACE to use for both injection and capture (default: ath0)") { |interface| options.interface = interface }
        opts.on("-j INTERFACE", "--inject INTERFACE", "The INTERFACE to use for injection (default: ath0)") { |interface| options.inject = interface }
        opts.on("-c INTERFACE", "--capture INTERFACE", "The INTERFACE to use for capture (default: ath0)") { |interface| options.capture = interface }
        opts.on("-d DRIVER", "--driver DRIVER", "The driver used for injection (default: madwifing)") { |driver| options.driver = driver }
        opts.on("-h CHANNEL", "--channel CHANNEL", "The channel to listen on (default: 11)") { |channel| options.channel = channel.to_i }
        opts.on("-s", "--speed", "Turn down the delay between emits, to scan more quickly (default: false)") { options.fast = true }

        opts.separator("")
        opts.separator("Output options:")
        opts.on("-f SVGPREFIX", "--fpdiagram SVGPREFIX", "Write a fingerprint diagram for each probe used, using SVGPREFIX") { |svgprefix| options.fpdiagram = svgprefix }
        opts.on("-p SVGPREFIX", "--plot SVGPREFIX", "Write a plot file for each probe used, using SVGPREFIX") { |svgprefix| options.plot_prefix = svgprefix }
        
        opts.separator("")
        opts.separator("Training options:")
        opts.on("-t", "--train", "Train baffle with a new device fingerprint") { options.train = true }

        opts.separator("")
        opts.separator("Common options:")
        opts.on("-v", "--verbose", "More detailed output") { options.verbose = true }
        opts.on("-?", "--help", "Show this message") { puts opts.help; exit }
        opts.on("--version", "Print the version") { puts opts.ver; exit }
          
        opts.separator("")
        opts.separator("Other options:")
        opts.on("-g", "--gui", "Show gui") { options.gui = true }
      end
    
      value = opts.parse!(args).first

      if value =~ /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/
        options.bssid = value
      else
        options.essid = value
      end
    
      unless options.gui? || options.bssid || options.essid
        puts opts.help 
        exit
      end

      options
    end
  end
end
