require File.join(File.dirname(__FILE__), "..", "probe.rb")

module Baffle
  module Probes
    class Flags < Baffle::Probe
      inject Baffle::Dot11::Broadcast.new(:flags => 1..255)

      capture(false) do |packet|
        { packet.flags => true }
      end
      
      # TODO: Should have a classifier in here as well, e.g.:
      # classify "Linksys", [true, false, true,...]
    end
  end
end
