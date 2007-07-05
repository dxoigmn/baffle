require "baflle"

probe_request = Dot11.new(:subtype => 0x4,
                          :type =>    0x0,
                          :proto =>   0x0,
                          :fc =>      0x00,
                          :id =>      0x0000,
                          :addr1 =>   "ff:ff:ff:ff:ff:ff",
                          :addr2 =>   "ba:aa:ad:f0:00:0d",
                          :addr3 =>   "ff:ff:ff:ff:ff:ff",
                          :sc =>      0x0100) /
                Dot11Elt.new(:id =>           0x00,
                             :info_length =>  0x00,
                             :info =>         "") /
                Dot11Elt.new(:id =>           0x01,
                             :info_length =>  0x08,
                             :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*"))
                             
probe_response = Dot11.new(:subtype => 0x5,
                           :addr1 =>   "ba:aa:ad:f0:00:0d")

add_rule :probe,
         :send => probe_request,
         :expect => probe_response,
         :pass => lambda { |response| return "Got probe response!\n" + pretty_print(response.data) },
         :fail => "No probe reponse!"

#(wlan[4:2] = 0xbaad) && (wlan[6:4] = 0xadf0000d)

puts eval("ath0", "madwifing", :probe)