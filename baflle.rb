$: << "specialized"
require "capture"
require "packetset"
require "specialized/dot11"
require "thread"
require "Lorcon"
require "timeout"


class CaptureQueue < Queue
  def initialize(device)
    super()
    @sniff = false
    @capture = nil
    @mutex = Mutex.new
    @capture_mutex = Mutex.new
    @capture_mutex.lock
    @thread = Thread.new do
      @capture = Capture.open(device)
      @capture_mutex.unlock
      @capture.each do |pkt|
        self.push(pkt) if @sniff
        #puts "pushed #{pkt.inspect}" if @sniff
      end
    end
    
    sleep 2
  end
  
  def start(filter = "")
    @capture_mutex.lock	
    self.clear

    @capture.filter = filter
    @sniff = true
    @capture_mutex.unlock
  end
  
  def stop
    self.clear
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
        current_mac = nil

        rule[:send].each do |packet|
          p packet.data
          
          current_mac = packet.addr1 if current_mac == nil
          packet.addr1 = current_mac.next!
          
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
  
  def send_p(packet, count=1)
    @device.write(packet, count, 0)
  end
  
  def eval_packet(rule, packet)
    filter = rule[:expect].kind_of?(String) ? rule[:expect] : ""
    filter = rule[:filter] if rule[:filter]
    
    @capture.start(filter)
    send_p packet, 3
        
    # Wait for response, timing out as necessary
    response = nil
    
    begin
      Timeout::timeout(rule[:timeout] || 2) do
        # Loop until we receive an acceptable response.
        while response == nil
          response = Radiotap.new(@capture.pop[0..-5]).payload
          expect = rule[:expect]

          case true
            when expect.kind_of?(Packet) || expect.kind_of?(Hash)
              response = nil unless response =~ expect
            when expect.kind_of?(Proc)
              response = nil unless expect[response]
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
