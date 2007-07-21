$: << "new_order"
require "capture"
require "packetset"
require "new_order/dot11"
require "new_order/radiotap"
require "thread"
require "Lorcon"
require "timeout"

module Baflle
  def add_rule(name, args)
    @rules ||= {}
    @rules[name] = args
  end
  
  def eval(interface, driver, name)
    begin
      @device = Lorcon::Device.new(interface, driver, 1)
      @interface = interface
      
      eval_rule @rules[name], nil
    rescue RuntimeError
      puts "Unable to put card into monitor / injection mode. Typically you have to be root to do this."
      exit
    end
  end
  
  private
  
  def eval_rule(rule, response)
    case rule[:send]
      when Proc
        rule[:send] = rule[:send][response]
        eval_rule rule, response
      when PacketSet
        # Here we are assuming that we want a response for each 
        # packet from a packetset, in contrast to having a single
        # response to a set of packets.
        return_values = []

        rule[:send].each do |packet|
          p packet.data
          
          value = eval_packet(rule, packet)
          
          p value
          
          return_values << value
          sleep 2
        end
        
        return return_values
      when Packet
        return eval_packet(rule, rule[:send])
    end
  end
  
  def send_p(packet)
    @device.write(packet, 1, 0)
  end
  
  def eval_packet(rule, packet)
    # Setup some capture parameters
    capture_options = { :device => @interface }
    capture_options[:filter] = rule[:filter] if rule[:filter]
    
    capture = Capture.open(capture_options)
    responses = []    

    # Send packet along...
    send_p packet
    
    # ...and now capture packets for rule[:timeout] seconds
    begin
      Timeout::timeout(rule[:timeout] || 2) do
        capture.each { |pkt| responses << pkt }
      end
    rescue Timeout::Error
      # Finished capturing packets.
    end
    
    capture.close
    
    # Find a packet in the responses array that matches what
    # we are looking for.
    response = nil    
    responses.each do |pkt|
      pkt = pkt[0..-5]        # Get rid of FCS
      pkt = Radiotap.new(pkt) # Parse radiotap header
      pkt = pkt.frame         # Get 802.11 frame
      expect = rule[:expect]
      
      # Process pkt with respect to expect
      case expect
        when Packet
          response = pkt if pkt =~ expect
        when Proc
          response = pkt if expect[pkt]
        when NilClass
          response = pkt
        when Enumerable
          response = pkt if expect.include?(pkt)
      end
      
      break if response != nil
    end
    
    # Evaluate next rule/proc
    process_next_rule ((response != nil) ? rule[:pass] : rule[:fail]), response
  end

  def process_next_rule(rule, response)
    case rule
      when Symbol
        fail "Bad next rule." if !@rules.has_key?(rule)
        eval_rule @rules[rule], response
      when Proc
        process_next_rule rule[response], response
      else
        return rule
    end
  end
  
  def pretty_print(data)
    str = ""
    data.each_byte do |byte|
      str += ("0" + byte.to_s(16))[-2,2] + " "
    end
    str
  end
end

include Baflle # put it in the kernel
