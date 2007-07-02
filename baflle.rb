$: << "new_order"
require "capture"
require "packetset"
require "new_order/dot11"
require "thread"
require "Lorcon"
require "timeout"

INTERFACE = "ath0"
DRIVER = "madwifing"

#  require 'thread'
#
#  queue = Queue.new
#
#  producer = Thread.new do
#    5.times do |i|
#      sleep rand(i) # simulate expense
#      queue << i
#      puts "#{i} produced"
#    end
#  end
#
#  consumer = Thread.new do
#    5.times do |i|
#      value = queue.pop
#      sleep rand(i/2) # simulate expense
#      puts "consumed #{value}"
#    end
#  end
#
#  consumer.join

class CaptureQueue < Queue
  def initialize(device)
    super()
    @capture = false
    @thread = Thread.new do
      params = { :device => device }
      
      Capture.open(params) do |capture|
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
  
  def eval(name)
    device = Lorcon::Device.new(INTERFACE, DRIVER, 1)
    capture = CaptureQueue.new(INTERFACE)
    rule = @rules[name]

    case rule[:send]
      when PacketSet
        return_values = []
        
        rule[:send].each do |params|
          packet_class = params[:class]
          params.delete :class
          return_values << eval_rule(device, capture, rule, packet_class.new(params))
        end
        
        return return_values
      when Packet
        return eval_rule(device, capture, rule, rule[:send])
    end
  end
  
  private
  
  def eval_rule(device, capture, rule, packet)
    # Send packet
    device.write(packet.data, 1, 0)
    capture.start
    
    # Wait for response, timing out as necessary
    response = nil
    
    begin
      Timeout::timeout(rule[:timeout] || 10) do
        while response == nil
          response = capture.pop
          
          case rule[:expect]
            when PacketSet
              response == nil if !rule[:expect].include?(response)
            when Packet
              response == nil if response != rule[:expect]
          end
        end
      end
    rescue Timeout::Error
      response = nil
    end
    
    capture.stop
    
    # Process packet
    next_rule = response != nil ? rule[:pass] : rule[:fail]
  
    # Evaluate next rule/proc
    case next_rule
      when Symbol
        eval_rule @rules[next_rule]  # TODO: Check for nil
      when String
        return next_rule
      when Proc
        return next_rule.call
    end
  end
end

include Baflle # put it in the kernel