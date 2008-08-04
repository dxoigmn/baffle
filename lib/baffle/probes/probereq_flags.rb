probe "probereq_flags" do
  repeat 5

  inject(0..255) do |options, flags|
    local_bssid = "f0:00:0d:00:00:" + "00#{flags.to_s(16)}".slice(-2..-1)

    Dot11::Dot11.new(:subtype =>  0x4,
                     :type =>     0x0,
                     :version =>  0x0,
                     :flags =>    flags,
                     :duration => 0x0000,
                     :addr1 =>    options.bssid,
                     :addr2 =>    local_bssid,
                     :addr3 =>    options.bssid,
                     :sc =>       0x0000, # This is auto-filled in by the driver.
                     :payload =>  Dot11::Dot11::Dot11ProbeReq.new /
                                  Dot11::Dot11::Dot11Elt.new(
                                    :id =>           0x00,
                                    :info_length =>  options.essid.length,
                                    :info =>         options.essid) /
                                  Dot11::Dot11::Dot11Elt.new(
                                    :id =>           0x01,
                                    :info_length =>  0x08,
                                    :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*")))
  end

  capture(Dot11::Dot11.new(:type => 0, :subtype => 0x5, :addr1 => "f0:00:0d:00:00:00/32")) do |packet|
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
