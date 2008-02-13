require File.join(File.dirname(__FILE__), 'lib/dot11/dot11')
require File.join(File.dirname(__FILE__), 'lib/capture/capture')
require File.join(File.dirname(__FILE__), 'util')
#require 'linalg'

module Baffle
  module Probes
    def self.<<(probe)
      @probes << probe
    end
    
    def self.load
      return if @probes
      
      @probes = []
      
      Dir[File.join(File.dirname(__FILE__), "probes", "*.rb")].each do |file|
        Kernel.load file
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
      @options          = Baffle.instance_variable_get("@options") # Fugly, FIXME
      @name             = name
      @training_data    = Hash.new {|hash, key| hash[key] = []}
      @names            = []
      @injection_data   = nil
      @capture_filters  = []

      instance_eval(&block)
      
      # I think this is a good place to call learn... we should have all training samples by now
      learn
    end
    
    def run
      sniff_thread = sniff(@options.capture) do |packet|
        @capture_filters.each do |filter|
          if filter[0] =~ packet.data
            filter[1].call(packet)
          end
        end
      end
      
      Baffle::emit(@options.inject, @options.driver, @options.channel, @injection_data, @options.fast? ? 0.1 : 0.5)
      
      sniff_thread.kill
    end
    
    def sniff(capture_if, &block)
      Thread.new do
        # We want to only listen for packets that match the filters we've defined
        filter = @capture_filters.reject{|f| f[0] == :timeout}.map{|f| "(#{f[0].expression})"}.join(" || ")
        p filter
        Baffle::sniff(:device => capture_if, :filter => filter, &block)
      end
    end

    def inject(packets)
      @injection_data = packets
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
    
    def timeout(&block)
      @capture_filters << [:timeout, block]
    end

    def train(name, vector)
      @training_data[name] << vector
    end
    
    # Gets called when all training samples have been loaded
    def learn
	    return

      # The code below assumes at least two training values, and doing it with any fewer
      # doesn't make much sense anyway
      return if @training_data.size < 2
      
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
    end

    # Build a hash of hypotheses on the given vector, with confidence ratings on each hypothesis
    def hypothesize(vector)
      similarities = Hash.new{|hash, key| hash[key] = []}
      
      vector_embedded = vector * @u2 * @eig2.inv
      
      @v2.rows.each_with_index do |row, i|
        similarities[@names[i]] << vector_embedded.transpose.dot(row.transpose) / (row.norm * vector_embedded.norm)
      end
      
      # TODO: un-hardcode the constant rejection distance
      similarities.reject{|k, sim| sim < 0.9}.sort_by{|x| x[1]}
      
    end
  end
end

def probe(name, &block)
  Baffle::Probes << Baffle::Probe.new(name, &block)
end
