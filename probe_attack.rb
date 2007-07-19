#!/usr/bin/ruby
require "baflle-ng"

if ARGV.length < 2
  puts "Usage: ./probe_attack.rb [local mac] [remote mac] [essid]"
  exit
end

$localmac = ARGV[0]
$remotemac = ARGV[1]
$essid = ARGV[2]

#$blackhole1 = "00:18:F8:F4:53:1C"
#$blackhole2 = "00:12:0E:51:AC:55"
#$aruba =      "00:0b:86:80:e4:e0"

$probe_addedum = Dot11ProbeReq.new() /
                 Dot11Elt.new(:id =>           0x00,
                              :info_length =>  $essid.length,
                              :info =>         $essid) /
                 Dot11Elt.new(:id =>           0x01,
                              :info_length =>  0x08,
                              :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*"))

$probes = PacketSet.new(Dot11, 
                        :subtype =>   0x4,
                        :type =>      0x0,
                        :version =>   0x0,
                        :flags =>     0..20,
                        :duration =>  0x0000,
                        :addr1 =>     $remotemac,
                        :addr2 =>     $localmac,
                        :addr3 =>     $remotemac,
                        :sc =>        0x0100,
                        :payload =>   $probe_addedum)
                                                    
$probe_response = Dot11.new(:type =>     0x0,
                            :subtype =>  0x5,
                            :addr1 =>    $localmac)
                           
add_rule :probe,
         :send => $probes,
         :expect => $probe_response,
         :pass => "Got probe response!",
         :fail => "No probe response!"#,
         #:filter => "wlan[0] == 0x50"
      
puts eval("ath0", "madwifing", :probe)
