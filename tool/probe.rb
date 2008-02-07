module Baffle
  module Probes
    def self.load
      return if @loaded
      
      Dir[File.join(File.dirname(__FILE__), "probes", "*.rb")].each do |file|
        require file
      end
      
      @loaded = true
    end
    
    def self.each
      load unless @loaded
      
      Baffle::Probes.constants.each do |constant|
        klass = Baffle::Probes.const_get(constant)
        yield klass if klass.ancestors.include?(Baffle::Probe)
      end
    end
  end
  
  class Probe
    def self.inject(packets)
      define_method(:inject) do |options|
        puts "Using options: #{options}"
        
        packets.each do |packet|
          puts "Would send packet #{packet}"
        end
      end
    end
    
    def self.capture(default = nil)
      fail unless block_given?
      
      define_method(:capture) do |packets|
        mapping = Hash.new(default)
        
        packets.each do |packet|
          mapping.merge!(yield(packet))
        end
        
        mapping
      end
    end
    
    @@classifications = []
    
    def self.classify(name, vector)
      @@classifications << [name, vector]
    end
    
    def classify(vector)
      @@classifications.inject({}) do |hash, classification|
        name        = classification[0]
        vector      = classification[1]
        confidence  = 0.5 # TODO: Actually calculate confidence
        
        hash[name]  = confidence
        hash
      end
    end
  end
end
