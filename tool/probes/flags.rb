probe "flags" do
  inject Baffle::Dot11.new(:subtype =>   0x4,
                           :type =>      0x0,
                           :version =>   0x0,
                           :flags =>     0..255,
                           :duration =>  0x0000,
                           :addr1 =>     @options.bssid,
                           :addr2 =>     "ba:aa:ad:f0:00:0d",
                           :addr3 =>     @options.bssid,
                           :sc =>        0x0000, # This is auto-filled in by the driver.
                           :payload =>   Baffle::Dot11::Dot11ProbeReq.new / 
                                            Baffle::Dot11::Dot11Elt.new(:id =>           0x00,
                                                         :info_length =>  @options.essid.length,
                                                         :info =>         @options.essid) /
                                            Baffle::Dot11::Dot11Elt.new(:id =>           0x01,
                                                         :info_length =>  0x08,
                                                         :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*")))
  
  capture Baffle::Dot11.new(:type => 0, :subtype => 0x5, :addr1 => "00:0e:35:75:4e:75") do
    1
  end
  
  timeout do
    0
  end
  
  train "Linksys", [1, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  train "Apple", [1, 1, 1, 0, 0, 0, 0, 1, 1, 0]
end
