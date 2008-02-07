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
      @@size = packets.size
      
      define_method(:inject) do |options|
        packets.each do |packet|
          # TODO: Send packet using options
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
        
        (0...@@size).map { |key| mapping[key] }
      end
    end
    
    @@classifications = []
    
    def self.classify(name, vector)
      @@classifications << [name, vector]
    end
    
    def classify(vector)
      @@classifications.inject({}) do |hash, classification|
        name        = classification[0]
        cvector     = classification[1]
        
        # TODO: Really calculate confidence...
        confidence  = (vector == cvector ? 1 : 0)
        
        hash[name]  = confidence
        hash
      end
    end
  end
end
