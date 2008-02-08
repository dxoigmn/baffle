require 'matrix'

class Vector
  def magnitude
    sumsqs = 0.0
    
    self.size.times do |i|
      sumsqs += self[i] ** 2.0
    end
    
    Math.sqrt(sumsqs)
  end
end

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
    def self.filter(filter)
      define_method(:filter) do
        filter
      end
    end
    
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
    
    @@training_data = []
    
    def self.train(name, vector)
      @@training_data << [name, vector]
    end
    
    def classify(vector)
      @@training_data.inject({}) do |hash, classification|
        name        = classification[0]
        cvector     = classification[1]
        hash[name]  = (Vector[*cvector] - Vector[*vector]).magnitude
        hash
      end
    end
  end
end
