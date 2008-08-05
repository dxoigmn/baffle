require 'rubygems'
require 'dot11'
require 'rb-pcap'
require 'facets/array/product'
require 'linalg'
require 'thread'
require 'yaml'

require File.expand_path(File.join(File.dirname(__FILE__), 'util'))

module Baffle
  module Probes
    def self.<<(probe)
      @probes << probe
    end
    
    def self.load
      return if @probes
      
      @probes = []
      
      Dir[File.join(File.dirname(__FILE__), "probes", "*.rb")].each do |file|
        require File.expand_path(file)
      end
      
      probe_data = YAML::load(File.open(File.join(File.dirname(__FILE__), '..', '..', 'data', 'probes.yml')))
      
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
    
    def self.total_injection_values
      self.load
      
      @probes.inject(0) { |sum, probe| sum += probe.injection_values.size * probe.repeats }
    end
  end
  
  class Probe
    attr_reader :name, :training_data, :injection_values, :injection_proc, :filter_procs, :capture_procs
    
    def initialize(name, &block)
      @name             = name
      @training_data    = Hash.new {|hash, key| hash[key] = []}
      @names            = []
      @injection_values = nil
      @injection_proc   = nil
      @filter_procs     = {}
      @capture_procs    = {}
      @repeat           = 1
      
      instance_eval(&block)
    end
    
    def run(options, &block)
      unless options.train?
        return nil unless learn
      end

      samples = []
      
      @repeat.times do |i|
        samples[i] = []
        
        filters = {}
        @filter_procs.each do |name, filter_proc|
          filter = filter_proc.call(options)
          
          case filter
          when Dot11::Packet
            filter = Dot11::PacketSet.new(Dot11::Dot11, :payload => filter) if !filter.kind_of?(Dot11::Dot11)
          when Dot11::PacketSet
            puts "filter is Dot11::PacketSet"
            filter = Dot11::PacketSet.new(Dot11::Dot11, :payload => filter) if filter.packet_class != Dot11::Dot11
          end
          
          filters[name] = Capture::Filter.new(filter.to_filter)
        end
        
        sniff_thread = Thread.new do
          filter = filters.values.map { |filter| "(#{filter.expression})" }.join(" || ")
          
          Baffle::sniff(:device => options.capture, :filter => filter) do |packet|
            filters.each do |name, filter|
              samples[i] << @capture_procs[name].call(packet) if filter =~ packet.data
            end
          end
        end
        
        Baffle::emit(options, @injection_proc, @injection_values, &block)
        sniff_thread.kill
      end
      
      @vector = @compute_vector.call(samples)
    end
    
    def inject(car, *cdr, &block)
      @injection_proc   = block
      @injection_values = car.to_a rescue []
      @injection_values = @injection_values.product(*cdr.map{ |v| v.to_a rescue []})
    end
    
    def compute_vector(&block)
      @compute_vector = block
    end
    
    def filter(name, &block)
      @filter_procs[name] = block
    end
    
    def capture(name, &block)
      @capture_procs[name] = block
    end
    
    def repeat(count)
      @repeat = count
    end
    
    def repeats
      @repeat
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
      
      sorted_similarities = similarities.delete_if { |name, score| score.nan? }.sort_by { |name, score| -score }
      name, score = sorted_similarities.first
      
      name ||= 'Unknown'
      score ||= 'NaN'
      
      "#{name} (#{score})"
    end
  end
end

def probe(name, &block)
  Baffle::Probes << Baffle::Probe.new(name, &block)
end
