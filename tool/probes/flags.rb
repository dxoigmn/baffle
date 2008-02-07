require File.join(File.dirname(__FILE__), "..", "probe.rb")

module Baffle
  module Probes
    class Flags < Baffle::Probe
      inject Baffle::Dot11::Broadcast.new(:flags => 0..9)

      capture(0) do |packet|
        { packet.flags => 1 }
      end
      
      train "Linksys", [1, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    end
  end
end
