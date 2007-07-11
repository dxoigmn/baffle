require "baflle"

# Test to make sure that we are not sending packets twice.
# 

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
                             
probe_response = Dot11.new(:type =>     0x0,
                           :subtype =>  0x5,
                           :addr1 =>    "ba:aa:ad:f0:00:0d") /
                 Dot11ProbeResp.new() /
                 Dot11Elt.new(:id =>  0x00,
                              :info_length => 0x0d,
                              :info => "Nanda_test_AP")

def auth_request(response)
  puts "Responding to #{response.addr2}"
  Dot11.new(:subtype =>  0xb,
            :type =>     0x0,
            :version =>  0x0,
            :flags =>    0x00,
            :id =>       0x0000,
            :addr1 =>    response.addr2,
            :addr2 =>    "ba:aa:ad:f0:00:0d",
            :addr3 =>    response.addr2,
            :sc =>       0x0100) /
  Dot11Auth.new(:algo =>   0x0000,
                :seqnum => 0x0001,
                :status => 0x0000)           
end
            
auth_response = Dot11.new(:type =>    0x0,
                          :subtype => 0xb,
                          :addr1 =>   "ba:aa:ad:f0:00:0d")

def assoc_request(response)
  Dot11.new(:subtype =>  0x0,
            :type =>     0x0,
            :version =>  0x0,
            :flags =>    0x00,
            :id =>       0x0000,
            :addr1 =>    response.addr2,
            :addr2 =>    "ba:aa:ad:f0:00:0d",
            :addr3 =>    response.addr2,
            :sc =>       0x0100) /
  Dot11AssoReq.new(:capabilities =>     0x0001,
                   :listen_interval =>  0x000a) /
  Dot11Elt.new(:id =>           0x00,
               :info_length =>  0x0d,
               :info =>         "Nanda_test_AP") /
  Dot11Elt.new(:id =>           0x01,
               :info_length =>  0x04,
               :info =>         [0x02, 0x04, 0x0b, 0x16].pack("c*"))
end

assoc_response = Dot11.new(:type =>     0x0,
                           :subtype =>  0x1,
                           :addr1 =>    "ba:aa:ad:f0:00:0d")

add_rule :probe,
         :send => probe_request,
         :expect => probe_response,
         :pass => lambda { |response| puts "Got probe response!\n"; return :auth },
         :fail => lambda { |response| puts "No probe response!"; return false; }
      
add_rule :auth,
         :send => lambda { |response| auth_request response },
         :expect => auth_response,
         :pass => lambda { |response| puts "Got auth response!\n"; return :assoc },
         :fail => lambda { |response| puts "No auth response!"; return false; }

add_rule :assoc,
         :send => lambda { |reponse| assoc_request reponse },
         :expect => assoc_response,
         :pass => lambda { |response| puts "Got assoc response!\n"; return true },
         :fail => lambda { |response| puts "No assoc response!"; return false }

puts eval("ath0", "madwifing", :probe)
