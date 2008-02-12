# TODO: Implement lazy mac decomposition too
require 'packetset'

class String
  def indent(depth)
    indented = ""
    self.each_line do |line|
      indented += " " * depth + line
    end
    
    indented
  end
end

module Baffle
  class MACAddress
    include Comparable
  
    def initialize(address)
      if address.kind_of?(Integer)
        @address = [address].pack("Q").unpack("C8")[0, 6].reverse
      elsif address.kind_of?(String)
        @address = address.split(":").map {|octet| octet.to_i(16)}
      elsif address.kind_of?(Array)
        @address = address
      end 
    end
  
    def to_i
      ("\x00\x00" + @address.pack("C6")).reverse.unpack("Q")[0]
    end
  
    def to_s
      @address.map{|byte| "%02x" % byte}.join(":")
    end
  
    def inspect
      to_s
    end
  
    def to_arr
      @address
    end
  
    def [](index)
      @address[index]
    end
  
    def eql?(other)
      to_i == other.to_i
    end
  
    def ==(other)
      eql?(other)
    end
  
    def hash
      to_i.hash
    end
  end

  class Packet
    class <<self
      alias older_new new
    
      def new(parameters = {})
        # Maybe we shouldn't do it this way, but it looks prettier
        if !parameters.kind_of?(String) && parameters.values.any? {|v| v.kind_of?(Array) || v.kind_of?(Range)}
          Baffle::PacketSet.new(self, parameters)
        else
          older_new(parameters)
        end
      end
    end
    
    def initialize(parameters = {})
      if parameters.kind_of?(String)
        dissect(parameters)
      elsif parameters.kind_of?(Hash)
        parameters.each_pair do |key, value|
          send((key.to_s + "=").intern, value)
        end
      end
    end
  
    def =~(other)
      if other.kind_of?(Hash)
        other.each_pair do |key, value|
          return false if self.send(key) != value
        end
      
        return true
      end
    end
  end

  class Dot11 < Packet
    @@TYPENAMES = [["association request", "association response", "reassociation request", "reassociation response", "probe request", "probe response", "reserved0", "reserved1", "beacon", "ATIM", "disassociation", "authorization", "deauthorization", "reserved2", "reserved3", "reserved4"],
                   ["reserved0", "reserved1", "reserved2", "reserved3", "reserved4", "reserved5", "reserved6", "reserved7", "reserved8", "PS-poll", "RTS", "CTS", "ACK", "CF-end", "CF-end + CF-ack"],
                   ["data", "data + CF-ack", "data + CF-poll", "data + CF-ack + CF-poll", "null function (no data)", "CF-ack (no data)", "CF-poll (no data)", "CF-ack + CF-poll (no data)", "reserved0", "reserved1", "reserved2", "reserved3", "reserved4", "reserved5", "reserved6", "reserved7"],
                   ["reserved0", "reserved1", "reserved2", "reserved3", "reserved4", "reserved5", "reserved6", "reserved7", "reserved8", "reserved9", "reserved10", "reserved11", "reserved12", "reserved13", "reserved14", "reserved15"]]
  
    def subtype
      @subtype ||= 0
    end
  
    def subtype=(other)
      @subtype = other
    end
  
    def type
      @type ||= 0
    end

    def type=(other)
      @type = other
    end
  
    def version
      @version ||= 0
    end
  
    def version=(other)
      @version = other
    end
  
    def flags
      @flags ||= 0
    end
  
    def flags=(other)
      @flags = other
    end
  
    def duration
      @duration ||= 0
    end
  
    def duration=(other)
      @duration = other
    end
  
    def addr1
      @addr1 ||= 0
    end
  
    def addr1=(other)
      if other.kind_of?(Integer) || other.kind_of?(String)
        @addr1 = MACAddress.new(other)
      elsif other.kind_of?(MACAddress)
        @addr1 = other
      else
        raise "Unrecognized addr #{other.inspect}"
      end
    end

    def addr2
      @addr2 ||= 0
    end

    def addr2=(other)
      if other.kind_of?(Integer) || other.kind_of?(String)
        @addr2 = MACAddress.new(other)
      elsif other.kind_of?(MACAddress)
        @addr2 = other
      else
        raise "Unrecognized addr #{other.inspect}"
      end
    end

    def addr3
      @addr3 ||= 0
    end
  
    def addr3=(other)
      if other.kind_of?(Integer) || other.kind_of?(String)
        @addr3 = MACAddress.new(other)
      elsif other.kind_of?(MACAddress)
        @addr3 = other
      else
        raise "Unrecognized addr #{other.inspect}"
      end
    end
  
    def sc
      @sc ||= 0
    end
  
    def sc=(other)
      @sc = other
    end
  
    def addr4
      @addr4 ||= 0
    end
  
    def addr4=
      if other.kind_of?(Integer) || other.kind_of?(String)
        @addr4 = MACAddress.new(other)
      elsif other.kind_of?(MACAddress)
        @addr4 = other
      else
        raise "Unrecognized addr #{other.inspect}"
      end
    end
  
    def payload=(other)
      @payload = other
    end

    def data
      buffer = ""
    
      buffer = [(subtype << 4) | (type << 2) | version, flags, duration].concat(addr1.to_arr).pack("CCSC6")
    
      if (type == 1 && [0x0a, 0x0b, 0x0e, 0x0f].include?(subtype)) || (type != 1)
        buffer += addr2.to_arr.pack("C6")
      end
    
      if [0, 2].include?(type)
        buffer += addr3.to_arr.pack("C6")
      end
    
      if type != 1
        buffer += [sc].pack("v")
      end
    
      if type == 2 && flags & 0x03 == 0x03
        buffer += addr4.to_arr.pack("C6")
      end
    
      if payload
        buffer += payload.data
      end
    
      buffer    
    end
  
    def ==(other)
      eql?(other)
    end
  
    def eql?(other)
      return false unless other.kind_of?(Dot11)
    
      basics = subtype.eql?(other.subtype) && type.eql?(other.type) && version.eql?(other.version) &&
               flags.eql?(other.flags) && duration.eql?(other.duration) && addr1.eql?(other.addr1)
             
      return false unless basics
    
      if (type == 1 && [0x0a, 0x0b, 0x0e, 0x0f].include?(subtype)) || (type != 1)
        return false unless addr2.eql?(other.addr2)
      end
    
      if [0, 2].include?(type)
        return false unless addr3.eql?(other.addr3)      
      end
    
      if type != 1
        return false unless sc.eql?(other.sc)
      end
    
      if type == 2 && flags & 0x03 == 0x03
        return false unless addr4.eql?(other.addr4)
      end
    
      return true
    end
  
    def /(other)
      if @payload.nil?
        @payload = other
        return self
      end
    
      if @payload.respond_to?(:elements)
        @payload.elements << other
      end
    
      self
    end
  
    alias to_s data 
  
    def inspect
      binary_flags = flags.to_s(2) 
      flag_names = ['to-DS', 'from-DS', 'MF', 'retry', 'pw-mgt', 'MD', 'wep', 'order']
      set_flags = []
    
      8.times do |i|
        set_flags << flag_names[i] if binary_flags[7 - i] == ?1
      end
    
      "Dot11\n" + if @corrupt then " (corrupt)" else "" end +
      "----------------\n" +
      "type: ...... #{type} (#{%w(management control data reserved)[type]})\n" +
      "subtype: ... #{subtype} (#{@@TYPENAMES[type][subtype]})\n" + 
      "version: ... #{version}\n" +
      "flags: ..... #{"%#02x" % flags} (#{"0" * (8 - flags.to_s(2).length) + flags.to_s(2)}#{if set_flags.size > 0 then ' : ' + set_flags.join(', ') else '' end})\n" +
      "duration: .. #{duration}\n" +
      "addr1: ..... #{addr1}\n" +
      (if addr2 then "addr2: ..... #{addr2}\n" else "" end) +
      (if addr3 then "addr3: ..... #{addr3}\n" else "" end) +
      (if sc then "sc: ........ #{"%#02x" % sc} (fragment: #{sc & 0x0F}; sequence: #{(sc & 0xFFF0) >> 4})\n" else "" end) +
      (if addr4 then "addr4: ..... #{addr4}\n" else "" end) + 
      (if payload then "payload:\n#{payload.to_s.indent(6)}" else "" end)
    end
  
    # Lazily dissect the payload
    def payload
      return @payload if @payload
    
      payload_class = if (@flags & 0x40) == 0x40
        Dot11WEP
      elsif @type == 0
        [ Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, Dot11ProbeReq, Dot11ProbeResp, nil, nil,
          Dot11Beacon, Dot11ATIM, Dot11Disas, Dot11Auth, Dot11Deauth, nil, nil, nil,
          nil, nil, nil, nil, nil, nil, nil, nil,
          nil, nil, nil, nil, nil, nil, nil ][@subtype]
      elsif @type == 2
        if @subtype == 0
          Dot11Data
        elsif @subtype == 4
          Dot11NullData
        end  
      end
    
      return nil if payload_class.nil?
        
      @payload = payload_class.new(@rest) unless (payload_class == Dot11NullData || @rest.nil? || @rest.empty?)
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("CCSC6")
    
      @subtype = (fields[0] & 0xF0) >> 4
      @type = (fields[0] & 0x0C) >> 2
      @version = fields[0] & 0x03
    
      @flags = fields[1]
      @duration = fields[2]

      # The array2mac calculations could be lazy if we really needed speed
      @addr1 = MACAddress.new(fields[3..-1])

      @rest = data[10..-1]
    
      if (@type == 1 && [0x0a, 0x0b, 0x0e, 0x0f].include?(@subtype)) || (@type != 1)
        if !@rest || @rest.empty?
          @corrupt = true
          return
        end
      
        @addr2 = MACAddress.new(@rest.unpack("C6")) 
        @rest = @rest[6..-1]
      end
    
      if [0, 2].include?(@type)
        if !@rest || @rest.empty?
          @corrupt = true
          return
        end
      
        @addr3 = MACAddress.new(@rest.unpack("C6"))
        @rest = @rest[6..-1]
      end
    
      if @type != 1
        if !@rest || @rest.empty?
          @corrupt = true
          return
        end
      
        @sc = @rest.unpack("v")[0]
        @rest = @rest[2..-1]
      end
    
      if @type == 2 && @flags & 0x03 == 0x03
        if !@rest || @rest.empty?
          @corrupt = true
          return
        end
      
        @addr4 = MACAddress.new(@rest.unpack("C6"))
        @rest = @rest[6..-1]
      end
    end

  end

  class Dot11Elt < Packet
    attr_accessor :id, :info_length, :info
  
    def Dot11Elt.register_element(id, klass)
      @@registered_elements ||= {}
    
      @@registered_elements[id] = klass
    end
  
    def data
  	buffer = [id, info_length].pack("CC")
    
      buffer += info
    end
  
    def to_s
      "Dot11Elt\n" + 
      "------------\n" +
      "id: ............ #{id}\n" + 
      "info_length: ... #{info_length}\n" +
      "info: .......... #{info.inspect}\n"
    end
  
    private 
  
    def dissect(data)
      fields = data.unpack("CC")
    
      @id = fields[0]
      @info_length = fields[1]
    
      @info = data[2, @info_length]
    
      @rest = data[2 + @info_length..-1]
    end
  
    class << self    
      # Hook into new to "subclass on the fly"
      alias old_new new
    
      def new(parameters)
        return old_new(parameters) if self != Dot11Elt

        if parameters.kind_of?(String)
          elt_id = parameters.unpack("C")[0]

          if @@registered_elements && @@registered_elements[elt_id]
            return @@registered_elements[elt_id].new(parameters)
          else
            elt = Dot11Elt.allocate
            elt.send(:initialize, parameters)
          
            return elt
          end
        
        elsif parameters.kind_of?(Hash)
        
          if @@registered_elements && @@registered_elements[parameters[:id]]
             return @@registered_elements[parameters[:id]].new(parameters)
           else
             elt = Dot11Elt.allocate
             elt.send(:initialize, parameters)

             return elt
           end    
        end      
      
      end
    
      def element_id(id)
        @id = id
        Dot11Elt.register_element(id, self)
      end
    end
  end

  class Dot11EltSSID < Dot11Elt
    element_id 0
  
    def essid
      return @info
    end
  
    def to_s
      "Dot11EltSSID\n" + 
      "-------------\n" +
      "id: ............ 0\n" +
      "info_length: ... #{info_length}\n" + 
      "essid: ......... #{info.inspect} (#{essid})\n"
    end
  end

  class Dot11EltRates < Dot11Elt
    element_id 1
  
    def rates
      return @rates if @rates

      @rates = []
    
      @info.each_byte do |b|
        @rates << (b & 0x7f) / 2
      end
    
      @rates
    end
  
    def to_s
      "Dot11EltRates\n" + 
      "------------------\n" +
      "id: ............ 1\n" +
      "info_length: ... #{info_length}\n" + 
      "rates: ......... #{info.inspect} (#{rates.join(', ')})\n"
    end
  end

  class Dot11EltESR < Dot11Elt
    element_id 50
  
    def rates
      return @rates if @rates

      @rates = []
    
      @info.each_byte do |b|
        @rates << (b & 0x7f) / 2
      end
    
      @rates    
    end
  
    def to_s
      "Dot11EltESR\n" + 
      "------------------\n" +
      "id: ............ 50\n" +
      "info_length: ... #{info_length}\n" + 
      "rates: ......... #{info.inspect} (#{rates.join(', ')})\n"
    end  
  end

  module Dot11EltContainer
    def elements_by_id
      hash = {}
    
      elements.each do |element|
        hash[element.id] = element
      end
    
      hash
    end

    def elements
      if @elements.nil?
        @elements = []
      
        if @rest
          dissect_elements(@rest)
        end
      
        return @elements      
      end
    
      @elements
    end
  
    def element_data
      buffer = ""
        
      elements.each do |element|
        buffer += element.data
      end
    
      buffer
    end
  
    def element_to_s
      buffer = ""
    
      elements.each do |element|
        buffer += element.to_s + "\n"
      end
    
      buffer
    end
  
    def /(other)
      elements << other
    
      self
    end
  
    private
  
    def dissect_elements(data)
      @elements = []
    
      current_pos = 0
    
      while current_pos < data.length
        info_length = data[current_pos, 2].unpack("xC")[0]
        total_elt_length = 2 + info_length
        
        @elements << Dot11Elt.new(data[current_pos, total_elt_length])
      
        current_pos += total_elt_length
      end
    
    end
  end

  class Dot11Beacon < Packet
    attr_accessor :timestamp, :beacon_interval, :capabilities
  
    include Dot11EltContainer
  
    def data
      buffer = [timestamp & 0xFFFFFFFF, (timestamp & 0xFFFFFFFF00000000) >> 32, beacon_interval, capabilities].pack("V2vn")
        
      buffer += element_data
    end
  
    def to_s
      binary_caps = capabilities.to_s(2) 
      cap_names = ['ESS', 'IBSS', 'CF Pollable', 'CF Poll Request', 'Privacy', 'Reserved5', 'Reserved6', 'Reserved7', 'Reserved8', 'Reserved9', 'Reserved10', 'Reserved11', 'Reserved12', 'Reserved13', 'Reserved14', 'Reserved15', ]
      set_caps = []
    
      16.times do |i|
        set_caps << cap_names[i] if binary_caps[15 -i] == ?1
      end
    
      "Dot11Beacon\n" + 
      "-------------------------\n" +
      "timestamp: ......... #{timestamp}\n" +
      "beacon_interval: ... #{beacon_interval} (#{beacon_interval * 0.001024} seconds)\n" + 
      "capabilities: ...... #{capabilities} (#{"0" * (16 - binary_caps.length) + binary_caps}#{if set_caps.size > 0 then ' : ' + set_caps.join(', ') else '' end})\n" +
      "elements:\n" + 
      element_to_s.indent(7)
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("V2vn")
    
      p fields
    
      @timestamp = (fields[1] << 32) | fields[0]
      @beacon_interval = fields[2]
      @capabilities = fields[3]
        
      @rest = data[12..-1]
    end
  end

  class Dot11ATIM < Packet
    def dissect(data)
      raise "Not implemented"
    end
  end

  class Dot11Disas < Packet
    attr_accessor :reason
  
    def data
      [reason].pack("v")
    end
  
    def to_s
      "Dot11Disas\n" + 
      "-------------\n" + 
      "reason: #{reason}\n"
    end
  
    private
  
    def dissect(data)
      @reason = data.unpack("v")[0]
    end
  end

  class Dot11AssoReq < Packet
    attr_accessor :capabilities, :listen_interval
  
    include Dot11EltContainer
  
    def data
      buffer = [capabilities, listen_interval].pack("nv")
    
      buffer += element_data
    end
  
    def to_s
      "Dot11AssoReq\n" +
      "---------------\n" +
      "capabilities: ...... #{capabilities}\n" +
      "listen_interval: ... #{listen_interval}\n" + 
      "elements:\n" + 
      element_to_s.indent(7)    
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("nv")
    
      @capabilities = fields[0]
      @listen_interval = fields[1]
    
      @rest = data[4..-1]
    end
  end

  class Dot11AssoResp < Packet
    attr_accessor :capabilities, :status, :aid
  
    include Dot11EltContainer
  
    def data
      buffer = [capabilities, status, aid].pack("nvv")
    
      buffer += element_data
    end
  
    def to_s
      "Dot11AssoResp\n" +
      "---------------\n" +
      "capabilities: ... #{capabilities}\n" +
      "status: ......... #{status}\n" + 
      "aid: ............ #{aid}\n" + 
      "elements:\n" + 
      element_to_s.indent(7)    
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("nvv")
    
      @capabilities = fields[0]
      @status = fields[1]
      @aid = fields[2]
    
      @rest = data[6..-1]
    end
  end

  class Dot11ReassoReq < Packet
    attr_accessor :capabilities, :current_ap, :listen_interval
  
    include Dot11EltContainer
  
    def data
      buffer = [capabilities].concat(mac2array(current_ap)).concat([listen_interval]).pack("nC6v")
    
      buffer += element_data
    end
  
    def to_s
      "Dot11ReassoReq\n" +
      "---------------\n" +
      "capabilities: ...... #{capabilities}\n" +
      "current_ap: ........ #{current_ap}\n" + 
      "listen_interval: ... #{listen_interval}\n" + 
      "elements:\n" + 
      element_to_s.indent(7)
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("nC6v")
    
      @capabilities = fields[0]
      @current_ap = Packet.array2mac(fields[1, 6])
      @listen_interval = fields[7]
    
      @rest = data[10..-1]
    end
  end

  class Dot11ReassoResp < Packet
    include Dot11EltContainer
  
    def data
      element_data
    end
  
    def to_s
      "Dot11ReassoResp\n" +
      "---------------\n" +
      "elements:\n" + 
      element_to_s.indent(7)
    end
  
    private
  
    def dissect(data)
      @rest = data
    end
  end

  class Dot11ProbeReq < Packet
    include Dot11EltContainer
  
    def data
      element_data
    end
  
    def to_s
      "Dot11ProbeReq\n" +
      "---------------\n" +
      "elements:\n" + 
      element_to_s.indent(7)
    end
  
    private
  
    def dissect(data)
      @rest = data
    end
  end

  class Dot11ProbeResp < Packet
    attr_accessor :timestamp, :beacon_interval, :capabilities
  
    include Dot11EltContainer
  
    def data
      buffer = [timestamp & 0xFFFFFFFF, (timestamp & 0xFFFFFFFF00000000) >> 32, beacon_interval, capabilities].pack("V2vn")
    
      buffer += element_data
    end
  
    def to_s
      binary_caps = capabilities.to_s(2) 
      cap_names = ['ESS', 'IBSS', 'CF Pollable', 'CF Poll Request', 'Privacy', 'Reserved5', 'Reserved6', 'Reserved7', 'Reserved8', 'Reserved9', 'Reserved10', 'Reserved11', 'Reserved12', 'Reserved13', 'Reserved14', 'Reserved15', ]
      set_caps = []
    
      16.times do |i|
        set_caps << cap_names[i] if binary_caps[15 -i] == ?1
      end
    
      "Dot11ProbeResp\n" + 
      "-------------------------\n" +
      "timestamp: ......... #{timestamp}\n" +
      "beacon_interval: ... #{beacon_interval} (#{beacon_interval * 0.001024} seconds)\n" + 
      "capabilities: ...... #{capabilities} (#{"0" * (16 - binary_caps.length) + binary_caps}#{if set_caps.size > 0 then ' : ' + set_caps.join(', ') else '' end})\n" +
      "elements:\n" + 
      element_to_s.indent(7)    
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("V2vn")
    
      @timestamp = (fields[1] << 32) | fields[0]
      @beacon_interval = fields[2]
      @capabilities = fields[3]
    
      @rest = data[12..-1]
    end  
  end

  class Dot11Auth < Packet
    attr_accessor :algo, :seqnum, :status
  
    include Dot11EltContainer
  
    def data
      buffer = [algo, seqnum, status].pack("vvv")
    
      buffer += element_data
    end
  
    def to_s
      "Dot11Auth\n" + 
      "-------------\n" + 
      "algo: #{algo}\n" +
      "seqnum: #{seqnum}\n" +
      "status: #{status}\n"  
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("vvv")
    
      @algo = fields[0]
      @seqnum = fields[1]
      @status = fields[2]
    
      @rest = data[6..-1]
    end
  end

  class Dot11Deauth < Packet
    attr_accessor :reason

    def data
      [reason].pack("v")
    end
  
    def to_s
      "Dot11Deauth\n" + 
      "-------------\n" + 
      "reason: #{reason}\n"
    end

    private
  
    def dissect(data)
      @reason = data.unpack("v")[0]
    end  
  end

  class Dot11Data < Packet
    attr_accessor :payload
  
    def data
      payload.data
    end

    def to_s
      "Dot11Data\n" + 
      "-------------\n" + 
      "payload: \n#{payload.to_s.indent(6)}\n"  
    end
  
    def payload
      return @payload if @payload
    
      @payload = LLC.new(@rest)
    end
  
    def /(other)
      @payload = other
      self
    end  
  
    private
  
    def dissect(data)
      @rest = data
    end
  end

  class Dot11NullData < Packet
    def data
      ""
    end
  
    def to_s
      "Dot11NullData\n"
    end
  
    private
  
    def dissect(data)
      @rest = data
    end
  end

  class Dot11WEP < Packet
    def data

    end
  
    def to_s
      "Dot11WEP\n" + 
      "-------------\n" + 
      "unknown\n"
    end

    private
  
    def dissect(data)
      @rest = data
    end    
  end

  class LLC < Packet
    attr_accessor :dsap, :ssap, :control, :payload
  
    def data
      [dsap, ssap, control].pack("CCC") + payload.data
    end
  
    def to_s
      "LLC\n" + 
      "-------------\n" + 
      "dsap: #{dsap}\n" +
      "ssap: #{ssap}\n" +
      "control: #{control}\n" +
      (if payload then "payload:\n#{payload.to_s.indent(6)}" else "" end)
    end
  
    def payload
      return @payload if @payload
    
      @payload = SNAP.new(@rest)
    end
  
    def /(other)
      @payload = other
      self
    end  
  
    private
  
    def dissect(data)
      fields = data.unpack("CCC")
    
      @dsap = fields[0]
      @ssap = fields[1]
      @control = fields[2]

      @rest = data[3..-1]  
    end
  end

  class SNAP < Packet
    attr_accessor :oui, :code, :payload
  
    def data
      [oui, code].pack("QXv") + payload.data
    end
  
    def to_s
      "SNAP\n" +
      "-------\n" +
      "oui: #{oui}\n" +
      "code: #{code}\n" + 
      (if payload then "payload:\n#{payload.to_s.indent(6)}" else "" end)
    end
  
    def payload
      return @payload if @payload
    
      return @payload = Raw.new(@rest)
    end
  
    def /(other)
      @payload = other
      self
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("CCCv")

      @oui = fields[0] << 16 | fields[1] << 8 | fields[2]
      @code = fields[3]

      @rest = data[4..-1]     
    end
  end

  class Raw < Packet
    attr_accessor :data
  
    def to_s
      "Raw\n" +
      "------\n" +
      "data: #{data.inspect}\n"
    end
  
    private
  
    def dissect(data)
      @data = data
    end
  end

  class Radiotap < Packet
    attr_accessor :revision, :pad, :stuff_length, :stuff
  
    def data
      raise "This space intentionally left blank"
    end
  
    def to_s
      "Radiotap\n" + 
      "-------------\n" + 
      "payload:\n" +
      payload.to_s.indent(6)
    end
  
    def payload
      return @payload if @payload

      @payload = Dot11.new(@rest)
    end
  
    private
  
    def dissect(data)
      fields = data.unpack("CCv")
    
      @data = data
      @revision = fields[0]
      @pad = fields[1]
      @stuff_length = fields[2]
    
      @rest = data[@stuff_length..-1]
    end
  end
end