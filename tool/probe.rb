require 'gsl'

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
      @training_data    = Hash.new {|hash, key| hash[key] = []}
      @column_names     = []
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
      @training_data[name] << vector
      
      # Doing it this way to make sure we have the same row/column order in names as we do in our matrix.
      # (There are no guarantees that two iterations over the pairs in a hash will have the same order)
      row_matrix, @column_names = @training_data.inject([[], []]) do |result, pair| 
        result[0] += pair[1]
        pair[1].length.times { result[1] << pair[0] }
        result
      end
      
      # We need a matrix of column vectors
      column_matrix = row_matrix.tranpose
            
      m = GSL::Matrix[*column_matrix]
      
      u, vt, s = m.SV_decomp
      s = GSL::Matrix.diagonal(s)
      
      # Do we want more than 2 dimensions? TODO: test other numbers of dimensions
      @u2 = GSL::Matrix[u.column(0), u.column(1)]
      @v2 = GSL::Matrix[vt.column(0), vt.column(1)]
      @eig2 = GSL::Matrix[s.column(0).to_a.flatten[0,2], s.column(1).to_a.flatten[0,2]] 
    end

    # Build a hash of hypotheses on the given vector, with confidence ratings on each hypothesis
    def hypothesize(vector)
      similarities = []
      
      vector_embedded = vector * @@us2 ** @@eig2.inv
      
      @@v2.each_row do |row|
        similarities << vector_embedded.dot(row) / (row.norm * vector_embedded.norm)
      end
      
      # TODO: un-hardcode the constant rejection distance
      similarities.reject{|k, sim| sim < 0.9}.sort_by{|x| x[1]}
      
    end
  end
end

def probe(name, &block)
  Baffle::Probes << Baffle::Probe.new(name, &block)
end
