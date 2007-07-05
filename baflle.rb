$: << "new_order"
require "capture"
require "packetset"
require "new_order/dot11"
require "new_order/radiotap"
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
      @capture.each do |pkt|
        self.push(pkt) if @sniff
      end
    end
  end
  
  def start(filter = "")
    @mutex.lock
    self.clear

    @capture.filter = filter
    @sniff = true
    @mutex.unlock
  end
  
  def stop
    @sniff = false
  end
  
  def pop
    @mutex.lock
    ret = super
    @mutex.unlock
    ret
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
    # TODO: We probably want the response data returned as well.
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
    # Start capture
    capture.start( rule[:expect].kind_of?(String) ? rule[:expect] : "" )
    
    # Send packet
    device.write(packet, 1, 0)
    
    # Wait for response, timing out as necessary
    response = nil
    
    begin
      Timeout::timeout(rule[:timeout] || 100) do
        # Loop until we receive an acceptable response.
        while response == nil
          raw = capture.pop[0..-5]
          response = Radiotap.new(raw).frame
          expect = rule[:expect]
          
          case true
            when expect.kind_of?(Packet)
              expect.field_values.each do |name, value|
                response_value = response.send(name)
                response = nil if response_value != value
                break if response_value != value
              end
            when expect.kind_of?(String)
              break
            when expect.respond_to?(:include?)
              response = nil if !expect.include?(response)
            else
              fail "Bad expect type."
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
        return next_rule[response]
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