#!/usr/bin/ruby

require 'packetset'
require 'Lorcon'
require 'specialized/dot11'
require 'baflle-recv'

trap "INT" do
  puts "exiting"
  puts "clients"
  p $aps
  exit
end

#$ap = "ba:aa:ad:f0:00:0d"

$probe_response = Dot11.new(
                        :subtype =>   0x5,
                        :type =>      0x0,
                        :version =>   0x0,
                        :flags =>     0x0,
                        :duration =>  0x013a,
                        :addr1 =>     0,
                        :addr2 =>     0,
                        :addr3 =>     0,
                        :sc =>        0x0000) /
                        Dot11ProbeResp.new(:timestamp => 0, :beacon_interval => 0x0064, :capabilities => 0x0100) /
                          Dot11Elt.new(
                            :id =>            0x00,
                            :info_length =>   4,
                            :info =>          "baad") /
                          Dot11Elt.new(
                            :id =>            0x01,
                            :info_length =>   0x04,
                            :info =>          [0x82, 0x84, 0x0b, 0x16].pack("c*")) /
                          Dot11Elt.new(
                            :id =>            0x03,
                            :info_length =>   0x01,
                            :info =>          [0x0b].pack("c*"))

$beacon = Dot11.new(:type     => 0x0,
                    :subtype  => 0x8,
                    :version  => 0x0,
                    :flags    => 0x0,
                    :duration => 0x0,
                    :addr1    => "ff:ff:ff:ff:ff:ff",
                    :addr2    => 0,
                    :addr3    => 0,
                    :sc       => 0x0000) /
          Dot11Beacon.new(:timestamp => 0, :beacon_interval => 0x0064, :capabilities => 0x0100) /
          Dot11Elt.new(
            :id =>            0x00,
            :info_length =>   4,
            :info =>          "baad") /
          Dot11Elt.new(
            :id =>            0x01,
            :info_length =>   0x04,
            :info =>          [0x82, 0x84, 0x0b, 0x16].pack("c*")) /
          Dot11Elt.new(
            :id =>            0x03,
            :info_length =>   0x01,
            :info =>          [0x0b].pack("c*"))

def generate_address(parameter)
  MACAddress.new(0xbaaaad000000 | (parameter & 0xffffff))
end

@device = Lorcon::Device.new("ath0", "madwifing", 1)

def emit(packet)
  @device.write(packet, 1, 0)
end

$current_flag       = 0x00
$flags_responded    = Hash.new(0)
$num_beacons_sent   = 0
$last_current_flag  = 0

# Log auth requests
Thread.new do
  $retry_count = 0
  sniff :device => 'ath0', :filter => 'wlan[0] == 0xb0' do |packet|
    ap_address = generate_address($current_flag)
    
    next unless packet.addr1 == MACAddress.new('ff:ff:ff:ff:ff:ff') ||
                packet.addr1 == ap_address

    $flags_responded[packet.addr1.to_i & 0xff] += 1    
    
    $retry_count += 1 if packet.flags & 0x08 == 0x08
    $retry_count  = 0 if packet.flags & 0x08 == 0x00
    
    puts "#{packet.addr2} tried to authenticate with #{packet.addr1}!"  unless packet.flags & 0x08 == 0x08
    puts "#{packet.addr2} tried to authenticate with #{packet.addr1} (retry #{$retry_count})!" if packet.flags & 0x08 == 0x08
  end
end

# Beacon broadcast every 0.25 seconds
Thread.new do
  while true
    if $num_beacons_sent > 40
      #$current_flag      += 1
    end

    if ($last_current_flag != $current_flag)
      $num_beacons_sent   = 0
      $last_current_flag  = $current_flag
    end

    $beacon.flags = $current_flag  
    $beacon.addr2 = generate_address($current_flag)
    $beacon.addr3 = generate_address($current_flag)

    #puts "Sending beacon with #{$beacon.addr2.to_s}"

    emit $beacon.data
    $num_beacons_sent += 1
    
    sleep 0.25
  end
end

# Look for probe requests
sniff :device => 'ath0', :filter => 'wlan[0] == 0x40' do |packet|
    ap_address = generate_address($current_flag)
    
    next unless packet.addr1 == MACAddress.new('ff:ff:ff:ff:ff:ff') ||
                packet.addr1 == ap_address
    #next if $seen

    $probe_response.flags = $current_flag
    $probe_response.addr1 = packet.addr2
    $probe_response.addr2 = ap_address
    $probe_response.addr3 = ap_address
    $probe_response.payload.timestamp = (Time.now.to_f * 100).to_i
    
    emit $probe_response.data
    
    puts "responding to probe request from #{packet.addr2} with #{ap_address}!" unless packet.flags & 0x08 == 0x08
    puts "responding to probe request from #{packet.addr2} with #{ap_address} (retry)!" if packet.flags & 0x08 == 0x08
end

