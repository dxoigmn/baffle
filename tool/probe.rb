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
    def self.send(packets)
      define_method(:run) do |options|
        p options
        packets.each do |packet|
          p packet
        end
      end
    end
  end
end
