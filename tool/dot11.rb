module Baffle
  module Dot11
    class Broadcast
      def initialize(options = {})
        @options = options
      end
      
      def size
        10
      end
      
      def each
        (0...size).each do |i|
          yield i
        end
      end
    end
  end
end