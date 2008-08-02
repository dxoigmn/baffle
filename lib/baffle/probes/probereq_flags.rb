probe "probereq_flags" do
  repeat 5
  inject Dot11::Dot11.new(:subtype =>   0x4,
                           :type =>      0x0,
                           :version =>   0x0,
                           :flags =>     0..255,
                           :duration =>  0x0000,
                           :addr1 =>     Baffle.options.bssid,
                           :addr2 =>     "ba:aa:ad:f0:00:0d",
                           :addr3 =>     Baffle.options.bssid,
                           :sc =>        0x0000, # This is auto-filled in by the driver.
                           :payload =>   Dot11::Dot11::Dot11ProbeReq.new /
                                         Dot11::Dot11::Dot11Elt.new(
                                            :id =>           0x00,
                                            :info_length =>  Baffle.options.essid.length,
                                            :info =>         Baffle.options.essid) /
                                         Dot11::Dot11::Dot11Elt.new(
                                            :id =>           0x01,
                                            :info_length =>  0x08,
                                            :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*")))
  
  capture Dot11::Dot11.new(:type => 0, :subtype => 0x5, :addr1 => "ba:aa:ad:f0:00:0d/32") do
    1
  end
  
  timeout do
    0
  end
  
  compute_vector do |samples|
    vector = Array.new(256, 0)
  
    samples.each do |sample|
      sample.each_pair do |key, value|
        vector[key] += 1 if value != 0
      end
    end

    vector
  end
end
