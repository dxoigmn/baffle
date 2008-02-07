module Baffle
  module Dot11
    class Broadcast
      def initialize(options = {})
        @options = options
      end
      
      def each
        10.times do |i|
          yield i
        end
      end
    end
  end
end