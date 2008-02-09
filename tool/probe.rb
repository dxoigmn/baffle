module Baffle
  module Probes
    def self.<<(probe)
      @probes << probe
    end
    
    def self.load
      return if @probes
      
      @probes = []
      
      Dir[File.join(File.dirname(__FILE__), "probes", "*.rb")].each do |file|
        require file
      end
      
      @probes
    end
    
    def self.each
      load unless @loaded
      
      @probes.each do |probe|
        yield probe
      end
    end
  end

  class Probe
    attr_reader :name, :training_data, :injection_data, :capture_filters

    def initialize(name, &block)
      @name             = name
      @training_data    = []
      @injection_data   = nil
      @capture_filters  = []

      instance_eval(&block)
    end

    def inject(packets)
      @injection_data = packets
    end

    def capture(filter, &block)
      @capture_filters << [filter, block]
    end
    
    def timeout(&block)
      @capture_filters << [:timeout, block]
    end

    def train(name, vector)
      @training_data << [name, vector]
    end
  end
end

def probe(name, &block)
  Baffle::Probes << Baffle::Probe.new(name, &block)
end
