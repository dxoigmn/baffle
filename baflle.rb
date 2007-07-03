$: << "new_order"
require "capture"
require "packetset"
require "new_order/dot11"
require "thread"
require "Lorcon"
require "timeout"

class CaptureQueue < Queue
  def initialize(device)
    super()
    @sniff = false
    @capture = nil
    @mutex = Mutex.new
    @mutex.lock
    @thread = Thread.new do
      @capture = Capture.open(device)
      @mutex.unlock
      @capture.setdissector do |data| Dot11.new(data) end
      @capture.each do |pkt|
        #puts pkt.inspect if @sniff
        self.push(pkt) if @sniff
      end
    end
  end
  
  def start(filter = "")
    @mutex.lock
    @mutex.unlock
    self.clear
    
    @capture.filter = filter
    @sniff = true
  end
  
  def stop
    @sniff = false
  end
end

module Baflle
  def add_rule(name, args)
    @rules ||= {}
    @rules[name] = args
  end
  
  def eval(interface, driver, name)
    device = Lorcon::Device.new(interface, driver, 1)
    capture = CaptureQueue.new(interface)
    
    eval_rule device, capture, @rules[name]
  end
  
  private
  
  def eval_rule(device, capture, rule)
    case rule[:send]
      when PacketSet
        # Here we are assuming that we want a response for each packet from a packetset, in contrast to
        # having a single response to a set of packets.
        return_values = []
        
        rule[:send].each do |packet|
          return_values << eval_packet(device, capture, rule, packet)
        end
        
        return return_values
      when Packet
        return eval_packet(device, capture, rule, rule[:send])
    end
  end
  
  def eval_packet(device, capture, rule, packet)
    # Send packet
    device.write(packet, 1, 0)
    
    # Wait for response, timing out as necessary
    capture.start( rule[:expect].kind_of?(String) ? rule[:expect] : "" )
    response = nil
    
    begin
      Timeout::timeout(rule[:timeout] || 10) do
        # Loop until we receive an acceptable response.
        while response == nil
          response = capture.pop

          #puts "sent     = #{packet.inspect}"
          #puts "         = #{pretty_print(packet.data)}"
          #puts "expect   = #{rule[:expect].inspect}"
          #puts "         = #{pretty_print(rule[:expect].data)}"
          #puts "response = #{response.inspect}"
          #puts "         = #{pretty_print(response.data)}"
          #puts "data     = #{pretty_print(data.inspect)}"
          
          case true
            when rule[:expect].respond_to?(:include?)
              response = nil if !rule[:expect].include?(response)
            when rule[:expect].kind_of?(Packet)
              response = nil if response != rule[:expect]
            when rule[:expect].kind_of?(String)
              break
            else
              fail "Bad expect."
          end
        end
      end
    rescue Timeout::Error
      response = nil
    end
    
    capture.stop

    # Evaluate next rule/proc
    next_rule = (response != nil) ? rule[:pass] : rule[:fail]
  
    case next_rule
      when Symbol
        fail "Bad next rule." if !@rules.has_key?(next_rule)
        eval_rule device, capture, @rules[next_rule]
      when String
        return next_rule
      when Proc
        return next_rule.call
      else
        fail "Unknown next rule type."
    end
  end
  
  def pretty_print(data)
    str = ""
    data.each_byte do |byte|
      str += byte.to_s(16) + " "
    end
    str
  end
end

include Baflle # put it in the kernel