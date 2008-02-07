require File.join(File.dirname(__FILE__), "..", "probe.rb")

module Baffle
  module Probes
    class Flags < Baffle::Probe
      inject Baffle::Dot11::Broadcast.new(:flags => 1..255)

      capture(0) do |packet|
        { packet.flags => 1 }
      end
      
      # TODO: Should have a classifier in here as well, e.g.:
      classify "Linksys", [1, 0, 1]
    end
  end
end
