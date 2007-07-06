require "baflle"

probe_request = Dot11.new(:subtype => 0x4,
                          :type =>    0x0,
                          :version => 0x0,
                          :flags =>   0x00,
                          :id =>      0x0000,
                          :addr1 =>   "ff:ff:ff:ff:ff:ff",
                          :addr2 =>   "ba:aa:ad:f0:00:0d",
                          :addr3 =>   "ff:ff:ff:ff:ff:ff",
                          :sc =>      0x0100) /
                Dot11ProbeReq.new() /
                Dot11Elt.new(:id =>           0x00,
                             :info_length =>  0x00,
                             :info =>         "") /
                Dot11Elt.new(:id =>           0x01,
                             :info_length =>  0x08,
                             :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*"))
                             
probe_response = Dot11.new(:subtype => 0x5,
                           :addr1 =>   "ba:aa:ad:f0:00:0d")

auth_request = Dot11.new(:subtype =>  0xb,
                         :type =>     0x0,
                         :version =>  0x0,
                         :flags =>    0x00,
                         :id =>       0x0000,
                         :addr1 =>    "00:02:6f:34:52:41",
                         :addr2 =>    "ba:aa:ad:f0:00:0d",
                         :addr3 =>    "00:02:6f:34:52:41",
                         :sc =>       0x0100) /
               Dot11Auth.new(:algo =>   0x0000,
                             :seqnum => 0x0001,
                             :status => 0x0000)           
              
auth_response = Dot11.new(:subtype => 0xb,
                          :addr1 =>   "ba:aa:ad:f0:00:0d")
                          
assoc_request = Dot11.new(:subtype =>  0x0,
                          :type =>     0x0,
                          :version =>  0x0,
                          :flags =>    0x00,
                          :id =>       0x0000,
                          :addr1 =>    "00:02:6f:34:52:41",
                          :addr2 =>    "ba:aa:ad:f0:00:0d",
                          :addr3 =>    "00:02:6f:34:52:41",
                          :sc =>       0x0100) /
                Dot11AssoReq.new(:capabilities =>     0x0001,
                                 :listen_interval =>  0x000a) /
                Dot11Elt.new(:id =>           0x00,
                             :info_length =>  0x13,
                             :info =>         "Nanda_test_AP") /
                Dot11Elt.new(:id =>           0x01,
                             :info_length =>  0x04,
                             :info =>         [0x02, 0x04, 0x0b, 0x16].pack("c*"))
                             
assoc_response = Dot11.new(:subtype =>  1,
                           :addr1 =>    "ba:aa:ad:f0:00:0d")
add_rule :probe,
         :send => probe_request,
         :expect => probe_response,
         :pass => lambda { |response| puts "Got probe response!\n #{pretty_print(response.data)}"; return :auth },
         :fail => lambda { |response| puts "No probe response!"; return false; }
      
add_rule :auth,
         :send => auth_request,
         :expect => auth_response,
         :pass => lambda { |response| puts "Got auth response!\n #{pretty_print(response.data)}"; return :assoc },
         :fail => lambda { |response| puts "No auth response!"; return false; }

add_rule :assoc,
         :send => assoc_request,
         :expect => assoc_response,
         :pass => lambda { |response| puts "Got assoc response!\n #{pretty_print(response.data)}"; return true },
         :fail => lambda { |response| puts "No assoc response!"; return false }

puts eval("ath0", "madwifing", :probe)