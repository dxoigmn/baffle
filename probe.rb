require File.join(File.dirname(__FILE__), 'lib/dot11/dot11')
require File.join(File.dirname(__FILE__), 'lib/capture/capture')
require File.join(File.dirname(__FILE__), 'util')
require 'linalg'
require 'thread'
require 'yaml'

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
      
      probe_data = YAML::load(File.open(File.join(File.dirname(__FILE__), 'probe_data.yml')))
      
      @probes.each do |probe|
        next unless probe_data[probe.name]
       
        probe_data[probe.name].each do |name, vectors|
          vectors.each do |vector|
            probe.training_data[name] << vector
          end
        end
      end
      
      @probes
    end
    
    def self.each
      self.load
      
      @probes.each do |probe|
        yield probe
      end
    end
  end

  class Probe
    attr_reader :name, :training_data, :injection_data, :capture_filters

    def initialize(name, &block)
      @name             = name
      @training_data    = Hash.new {|hash, key| hash[key] = []}
      @names            = []
      @injection_data   = nil
      @capture_filters  = []
      @repeat           = 1

      instance_eval(&block)
    end
    
    def run(options)
      unless options.train?
        return nil unless learn
      end

      @samples = []
      
      @repeat.times do |i|
        @samples[i] = Hash.new(0)
        
        @emitter  = ConditionVariable.new
        @sniffer  = Mutex.new
        
        sniff_thread = Thread.new do
          # We want to only listen for packets that match the filters we've defined
          filter = @capture_filters.reject{|f| f[0] == :timeout}.map{|f| "(#{f[0].expression})"}.join(" || ")

          Baffle::sniff(:device => options.capture, :filter => filter) do |packet|
            @emitter.signal

            @capture_filters.each do |filter|
              if filter[0] =~ packet.data
                @samples[i][packet.addr1.to_i & 0xffff] = filter[1].call(packet)
              end
            end
          end
          
          @emitter.signal
        end

        @emitter.wait(@sniffer)

        Baffle::emit(options.inject, options.driver, options.channel, @injection_data, options.fast? ? 0.05 : 0.3)
        sniff_thread.kill
      end
      
      @vector = @compute_vector.call(@samples)
    end

    def inject(packets)
      @injection_data = packets
    end
    
    def compute_vector(&block)
      @compute_vector = block
    end

    def capture(filter, &block)
      case filter
      when Packet
        if !filter.kind_of?(Dot11)
          filter = PacketSet.new(Dot11, :payload => filter)
        end
      when PacketSet
        if filter.packet_class != Dot11
          filter = PacketSet.new(Dot11, :payload => filter)
        end
      end
      
      @capture_filters << [Capture::Filter.new(filter.to_filter), block]
    end
    
    def repeat(count)
      @repeat = count
    end
    
    def timeout(&block)
      @capture_filters << [:timeout, block]
    end
    
    # Gets called when all training samples have been loaded
    def learn
      # The code below assumes at least two training values, and doing it with any fewer
      # doesn't make much sense anyway
      return false if @training_data.size < 2
      
      # Doing it this way to make sure we have the same row/column order in names as we do in our matrix.
      # (there are no guarantees that two iterations over the pairs in a hash will have the same order)
      row_matrix, @names = @training_data.inject([[], []]) do |result, pair| 
        result[0] += pair[1]
        pair[1].length.times { result[1] << pair[0] }
        result
      end
      
      # We need a matrix of column vectors
      column_matrix = row_matrix.transpose
            
      m = Linalg::DMatrix[*column_matrix]
      
      u, s, vt = m.singular_value_decomposition
      vt = vt.transpose
      
      # Do we want more than 2 dimensions? TODO: test other numbers of dimensions
      @u2 = Linalg::DMatrix.join_columns [u.column(0), u.column(1)]
      @v2 = Linalg::DMatrix.join_columns [vt.column(0), vt.column(1)]
      @eig2 = Linalg::DMatrix.columns [s.column(0).to_a.flatten[0,2], s.column(1).to_a.flatten[0,2]]

      true
    end

    # Build a hash of hypotheses on the given vector, with confidence ratings on each hypothesis
    def hypothesize(vector)
      similarities = []
      
      vector_embedded = Linalg::DMatrix[vector] * @u2 * @eig2.inv

      @v2.rows.each_with_index do |row, i|
        similarities << [@names[i], vector_embedded.transpose.dot(row.transpose) / (row.norm * vector_embedded.norm)]
      end
    
      name, score = similarities.sort_by { |name, score| -score }.first

      "#{name} (#{score})"
    end
  end
end

def probe(name, &block)
  Baffle::Probes << Baffle::Probe.new(name, &block)
end
