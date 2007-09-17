#!/usr/bin/ruby
require "baflle-send"

#$blackhole1 = "00:18:F8:F4:53:1C"
#$blackhole2 = "00:12:0E:51:AC:55"
#$aruba      = "00:0b:86:80:e4:e0"
#$airport    = "00:11:24:5c:7b:07"

if ARGV.length < 3
  puts "Usage: ./probe_attack_send_rates.rb [local mac] [remote mac] [essid]"
  exit
end

$localmac   = ARGV[0]
$remotemac  = ARGV[1]
$essid      = ARGV[2]

$probereq1 = Dot11ProbeReq.new() /
                 Dot11Elt.new(:id =>           0x00,
                              :info_length =>  $essid.length,
                              :info =>         $essid) /
                 Dot11Elt.new(:id =>           0x01,
                              :info_length =>  0x08,
                              :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*"))

$probereq2 = Dot11ProbeReq.new() /
                 Dot11Elt.new(:id =>           0x01,
                              :info_length =>  0x08,
                              :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*"))

$probereq3 = Dot11ProbeReq.new() /
                 Dot11Elt.new(:id =>           0x00,
                              :info_length =>  $essid.length,
                              :info =>         $essid)

$probereq4 = Dot11ProbeReq.new()

$probes = PacketSet.new(Dot11, 
                        :subtype =>   0x4,
                        :type =>      0x0,
                        :version =>   0x0,
                        :flags =>     0x0,
                        :duration =>  0x0000,
                        :addr1 =>     $remotemac,
                        :addr2 =>     $localmac,
                        :addr3 =>     $remotemac,
                        :sc =>        0x0000, # This is auto-filled in by the driver.
                        :payload =>   [$probereq1, $probereq2, $probereq3, $probereq4])

emit "ath2", "madwifing", $probes

