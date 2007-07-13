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
    #@mutex.lock
    self.clear

    @capture.filter = filter
    @sniff = true
    #@mutex.unlock
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
    begin
      @device = Lorcon::Device.new(interface, driver, 1)
      @capture = CaptureQueue.new(interface)
    
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
        # Here we are assuming that we want a response for each packet from a packetset, in contrast to
        # having a single response to a set of packets.
        return_values = []

        rule[:send].each do |packet|
          p packet.data
          return_values << eval_packet(rule, packet)
          sleep 5
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
    @capture.start( rule[:expect].kind_of?(String) ? rule[:expect] : "" )
    send_p packet
        
    # Wait for response, timing out as necessary
    response = nil
    
    begin
      Timeout::timeout(rule[:timeout] || 100) do
        # Loop until we receive an acceptable response.
        while response == nil
          response = Radiotap.new(@capture.pop[0..-5]).frame
          expect = rule[:expect]
          
          case true
            when expect.kind_of?(Packet)
              response = nil unless response =~ expect
            when expect.kind_of?(Proc)
              response = nil unless expect[response]
            when expect.kind_of?(String)
              break # First packet captured is good because of tcpdump filter.
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
    
    @capture.stop

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
