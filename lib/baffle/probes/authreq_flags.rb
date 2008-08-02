probe "authreq_flags" do
  repeat 5
  inject Dot11::Dot11.new(:subtype =>   0xb,
                          :type =>      0x0,
                          :version =>   0x0,
                          :flags =>     0..255,
                          :duration =>  0x0000,
                          :addr1 =>     Baffle.options.bssid,
                          :addr2 =>     "ba:aa:ad:f0:00:0d",
                          :addr3 =>     Baffle.options.bssid,
                          :sc =>        0x0000, # This is auto-filled in by the driver.
                          :payload =>   Dot11::Dot11::Dot11Auth.new(:algo   => 0x0000,
                                                                    :seqnum => 0x0001,
                                                                    :status => 0x0000)) 
  
  capture Dot11::Dot11.new(:type => 0, :subtype => 0xb, :addr1 => "ba:aa:ad:f0:00:0d/32") do
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
