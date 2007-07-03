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
    @capture = false
    @thread = Thread.new do
      Capture.open(device) do |capture|
        capture.each do |pkt|
          if @capture
            self.push pkt
          end
        end
      end
    end
  end
  
  def start
    self.clear
    @capture = true
  end
  
  def stop
    @capture = false
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
        return_values = []
        
        rule[:send].each do |params|
          packet_class = params[:class]
          params.delete :class
          return_values << eval_packet(device, capture, rule, packet_class.new(params))
        end
        
        return return_values
      when Packet
        return eval_packet(device, capture, rule, rule[:send])
    end
  end
  
  def eval_packet(device, capture, rule, packet)
    # Send packet
    device.write(packet.data, 1, 0)
    
    # Wait for response, timing out as necessary
    capture.start
    response = nil
    
    begin
      Timeout::timeout(rule[:timeout] || 10) do
        # Loop until we receive an acceptable response.
        while response == nil
          response = capture.pop
          
          case rule[:expect]
            when PacketSet
              response = nil if !rule[:expect].include?(response)
            when Packet
              response = nil if response != rule[:expect]
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
        eval_rule device, capture, @rules[next_rule]
      when String
        return next_rule
      when Proc
        return next_rule.call
    end
  end
end

include Baflle # put it in the kernel