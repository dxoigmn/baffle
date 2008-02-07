require File.join(File.dirname(__FILE__), "..", "probe.rb")

module Baffle
  module Probes
    class Flags < Baffle::Probe
      send Baffle::Dot11::Broadcast.new(:flags => 1..255)
      # TODO: Should have a classifier in here as well, e.g.:
      # classify "Linksys", [true, false, true,...]
    end
  end
end
