$: << "new_order"
require "capture"
require "packetset"
require "new_order/dot11"
require "thread"
require "Lorcon"
require "timeout"

INTERFACE = "ath0"
DRIVER = "madwifing"

module Baflle
  def add_rule(name, args)
    @rules ||= {}
    @rules[name] = args
  end
  
  def eval_rule(device, rule, packet)
    sent = false
    captured_packet = nil
  
    # Setup capture thread
    capture = Thread.new do
      params = {:device => INTERFACE}
      params[:timeout] = rule[:timeout] if rule[:timeout]
      params[:filter] = rule[:filter] if rule[:filter].kind_of?(String)
      
      puts "Opening capture..."
      
      Capture.open params do |capture|
        capture.each do |pkt|
          #puts "Received packet!"
          if sent
            puts "Got response!"
            captured_packet = pkt 
            break
          end
        end
      end
    end
  
    sleep 2
  
    # Send packet
    puts "Writing packet..."
    device.write(packet.data, 1, 0)
    sent = true
    puts "Waiting for response..."
    
    # Wait for capture thread to return
    capture.join
  
    # Process packet
    next_rule = (captured_packet || 
                (rule[:expect].kind_of?(PacketSet) && 
                  rule[:expect].include?(captured_packet))) ?
                rule[:pass] : rule[:fail]
  
    # Evaluate next rule/proc
    case next_rule.class.name
      when "Symbol"
        eval_rule @rules[next_rule]  # TODO: Check for nil
      when "Proc"
        next_rule.call
    end
  end
  
  def eval_rules
    device = Lorcon::Device.new(INTERFACE, DRIVER, 1)
  
    @rules.each do |name, rule|
      if rule[:send].kind_of? PacketSet
        rule[:send].each do |params|
          packet_class = params[:class]
          params.delete :class
          eval_rule device, rule, packet_class.new(params)
        end
      else
        eval_rule device, rule, rule[:send]
      end
    end
  end
end

include Baflle # put it in the kernel