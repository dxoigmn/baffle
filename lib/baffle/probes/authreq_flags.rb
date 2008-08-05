probe "authreq_flags" do
  inject(0..255) do |options, flags|
    local_bssid   = "ba:ad:"
    local_bssid  << options.bssid.slice(-5..-1)
    local_bssid  << ":00:"
    local_bssid  << "00#{flags.to_s(16)}".slice(-2..-1)
    
    Dot11::Dot11.new(:subtype =>   0xb,
                     :type =>      0x0,
                     :version =>   0x0,
                     :flags =>     flags,
                     :duration =>  0x0000,
                     :addr1 =>     options.bssid,
                     :addr2 =>     local_bssid,
                     :addr3 =>     options.bssid,
                     :sc =>        0x0000, # This is auto-filled in by the driver.
                     :payload =>   Dot11::Dot11::Dot11Auth.new(:algo   => 0x0000,
                                                               :seqnum => 0x0001,
                                                               :status => 0x0000)) 
  end
  
  filter :subtype_addr1 do |options|
    local_bssid   = "ba:ad:"
    local_bssid  << options.bssid.slice(-5..-1)
    local_bssid  << ":00:00/32"
    
    Dot11::Dot11.new(:type => 0, :subtype => 0xb, :addr1 => local_bssid)
  end
  
  capture :subtype_addr1 do |packet|
    packet.addr1.to_i & 0xff
  end
  
  compute_vector do |samples|
    vector = Array.new(256, 0)
    
    samples.each do |sample|
      sample.each do |flags|
        vector[flags] += 1
      end
    end
    
    vector
  end
end
