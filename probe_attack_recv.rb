#!/usr/bin/ruby
require "baflle-recv"

trap "INT" do
  puts "flags,count"
  $flags.each_with_index do |count, index|
    puts "%08b,%d" % [index, count]
  end
  
  abort
end

$flags = Array.new(256, 0)
$macs = {}
 
sniff "ath0" do |packet|
  next unless packet.type == 0
  next unless packet.subtype == 0x5
  next unless packet.addr1 =~ /ba:aa:ad:..:..:../ 
  next if $macs.has_key?(packet.addr1)
  
  flags = packet.addr1.split(":", 6)[5].to_i(16)

  puts "Got #{flags} from #{packet.addr1}"

  $flags[flags]      += 1
  $macs[packet.addr1] = true
end
