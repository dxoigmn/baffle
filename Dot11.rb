require 'packet'

class Dot11AddrMACField < MACField
  def is_applicable?(pkt)
    return true
  end

  def addfield(pkt, s, val)
    if self.is_applicable?(pkt)
      return MACField.addfield(self, pkt, s, val)
    else
      return s
    end
  end

  def getfield(pkt, s)
    if self.is_applicable(pkt)
      return MACField.getfield(self, pkt, s)
    else
      return s, nil
    end
  end
end

class Dot11Addr2MACField < Dot11AddrMACField
  def is_applicable?(pkt)
    if pkt.type == 1
      return [0xb, 0xa, 0xe, 0xf].include?(pkt.subtype) # RTS, PS-Poll, CF-End, CF-End+CF-Ack
    end

    return true
  end
end

class Dot11Addr3MACField < Dot11AddrMACField
  def is_applicable?(pkt)
    if [0,2].include?(pkt.type)
      return true
    end

    return 0
  end
end

class Dot11Addr4MACField < Dot11AddrMACField
  def is_applicable?(pkt)
    if pkt.type == 2
      if pkt.FCfield & 0x3 == 0x3 # To-DS and From-DS are set
        return true
      end
    end
    return false
  end
end

class Dot11 < Packet
  @@name = "802.11"
  @@fields_desc = [
    BitField.new("subtype", 0, 4),
    BitEnumField.new("type", 0, 2, ["Management", "Control", "Data", "Reserved"]),
    BitField.new("proto", 0, 2),
    FlagsField.new("FCfield", 0, 8, ["to-DS", "from-DS", "MF", "retry", "pw-mgt", "MD", "wep", "order"]),
    ShortField.new("ID",0),
    MACField.new("addr1", ETHER_ANY),
    Dot11Addr2MACField.new("addr2", ETHER_ANY),
    Dot11Addr3MACField.new("addr3", ETHER_ANY),
    Dot11SCField.new("SC", 0),
    Dot11Addr4MACField.new("addr4", ETHER_ANY) 
  ]

  def mysummary
    return self.sprintf("802.11 %Dot11.type% %Dot11.subtype% %Dot11.addr2% > %Dot11.addr1%")
  end

  def guess_payload_class(payload)
    if self.FCfield & 0x40
      return Dot11WEP
    else
      return Packet.guess_payload_class(self, payload)
    end
  end

  def answers(other)
    if other.kind_of?(Dot11)
      if self.type == 0: # management
        if self.addr1 != other.addr2 # check resp DA w/ req SA
          return false
        end
        if [[0, 1], [2, 3], [4, 5]].include?([other.subtype, self.subtype])
          return true
        end
        if self.subtype == 11 and other.subtype == 11 # auth
          return self.payload.answers(other.payload)
        end
      elsif self.type == 1 # control
        return false
      elsif self.type == 2 # data
        return self.payload.answers(other.payload)
      elsif self.type == 3 # reserved
        return false
      end
    end
    return false
  end

  def unwep(key=None, warn=1)
    if self.FCfield & 0x40 == 0
      if warn
        warning("No WEP to remove")
      end
      return
    end
    if @payload.payload.kind_of?(NoPayLoad)
      if key or conf.wepkey
        self.payload.decrypt(key)
      end
      if @payload.payload.kind_of?(NoPayLoad)
        if warn
          warning("Dot11 can't be decrypted. Check conf.wepkey.")
        end
        return
      end
    end
    self.FCfield &= ~0x40
    self.payload= self.payload.payload
  end
end


class Dot11SCField < LEShortField
  def is_applicable(pkt)
    return pkt.type != 1 # control frame
  end

  def addfield(pkt, s, val)
    if self.is_applicable(pkt)
      return LEShortField.addfield(pkt, s, val)
    else
      return s
    end
  end

  def getfield(pkt, s)
    if self.is_applicable(pkt)
      return LEShortField.getfield(pkt, s)
    else
      return s,None
    end
  end
end

capability_list = [ "res8", "res9", "short-slot", "res11",
                    "res12", "DSSS-OFDM", "res14", "res15",
                   "ESS", "IBSS", "CFP", "CFP-req",
                   "privacy", "short-preamble", "PBCC", "agility"]

reason_code = {0=>"reserved",1=>"unspec", 2=>"auth-expired",
               3=>"deauth-ST-leaving",
               4=>"inactivity", 5=>"AP-full", 6=>"class2-from-nonauth",
               7=>"class3-from-nonass", 8=>"disas-ST-leaving",
               9=>"ST-not-auth"}

status_code = {0=>"success", 1=>"failure", 10=>"cannot-support-all-cap",
               11=>"inexist-asso", 12=>"asso-denied", 13=>"algo-unsupported",
               14=>"bad-seq-num", 15=>"challenge-failure",
               16=>"timeout", 17=>"AP-full",18=>"rate-unsupported" }

class Dot11Beacon < Packet
  @@name = "802.11 Beacon"
  @@fields_desc = [ LELongField.new("timestamp", 0),
                    LEShortField.new("beacon_interval", 0x0064),
                    FlagsField.new("cap", 0, 16, capability_list) ]
end
    

class Dot11Elt < Packet
  @@name = "802.11 Information Element"
  @@fields_desc = [ ByteEnumField.new("ID", 0, {0=>"SSID", 1=>"Rates", 2=>"FHset", 3=>"DSset", 4=>"CFset", 5=>"TIM", 6=>"IBSSset", 16=>"challenge",
                                          42=>"ERPinfo", 47=>"ERPinfo", 48=>"RSNinfo", 50=>"ESRates",221=>"vendor",68=>"reserved"}),
                  FieldLenField.new("len", None, "info", "B"),
                  StrLenField.new("info", "", "len") ]

  def mysummary
    if self.ID == 0
      return "SSID=%s"%repr(self.info),[Dot11]
    else
      return ""
    end
  end
end

class Dot11ATIM < Packet
  @@name = "802.11 ATIM"
end

class Dot11Disas < Packet
  @@name = "802.11 Disassociation"
  @@fields_desc = [ LEShortEnumField.new("reason", 1, reason_code) ]
end

class Dot11AssoReq < Packet
  @@name = "802.11 Association Request"
  @@fields_desc = [ FlagsField.new("cap", 0, 16, capability_list),
                  LEShortField.new("listen_interval", 0x00c8) ]
end


class Dot11AssoResp < Packet
  @@name = "802.11 Association Response"
  @@fields_desc = [ FlagsField.new("cap", 0, 16, capability_list),
                  LEShortField.new("status", 0),
                  LEShortField.new("AID", 0) ]
end

class Dot11ReassoReq < Packet
  @@name = "802.11 Reassociation Request"
  @@fields_desc = [ FlagsField.new("cap", 0, 16, capability_list),
                  MACField.new("current_AP", ETHER_ANY),
                  LEShortField.new("listen_interval", 0x00c8) ]                 
end

class Dot11ReassoResp < Dot11AssoResp
  @@name = "802.11 Reassociation Response"
end

class Dot11ProbeReq < Packet
  @@name = "802.11 Probe Request"
end
    
class Dot11ProbeResp < Packet
  @@name = "802.11 Probe Response"
  @@fields_desc = [ LELongField.new("timestamp", 0),
                    LEShortField.new("beacon_interval", 0x0064),
                    FlagsField.new("cap", 0, 16, capability_list) ]
end
    
class Dot11Auth < Packet
  @@name = "802.11 Authentication"
  @@fields_desc = [ LEShortEnumField.new("algo", 0, ["open", "sharedkey"]),
                  LEShortField.new("seqnum", 0),
                  LEShortEnumField.new("status", 0, status_code) ]
  def answers(other)
    if self.seqnum == other.seqnum+1
      return true
    end
    return false
  end
end

class Dot11Deauth < Packet
  @@name = "802.11 Deauthentication"
  @@fields_desc = [ LEShortEnumField.new("reason", 1, reason_code) ]
end

class Dot11WEP < Packet
  @@name = "802.11 WEP packet"
  @@fields_desc = [ StrFixedLenField.new("iv", "\0\0\0", 3),
                    ByteField.new("keyid", 0),
                    StrField.new("wepdata",None,remain = 4),
                    IntField.new("icv",None) ]

  def post_dissect(s)
    # self.icv,    = struct.unpack("!I",self.wepdata[-4:])
    # self.wepdata = self.wepdata[:-4]
    self.decrypt()
  end

  def build_payload
    if self.wepdata.nil?
      return Packet.build_payload(self)
    end
    return ""
  end

  def post_build(p, pay)
    if self.wepdata.nil?
      key = conf.wepkey
      if key
        if self.icv.nil?
          pay += struct.pack("<I",crc32(pay))
          icv = ""
        else
          icv = p[4...8]
        end
        c = ARC4.new(self.iv+key)
        p = p[0...4]+c.encrypt(pay)+icv
      else
        warning("No WEP key set (conf.wepkey).. strange results expected..")
      end
    end
    return p
  end

  def decrypt(key=None)
    if key.nil?
      key = conf.wepkey
    end

    if key
      c = ARC4.new(self.iv+key)
      self.add_payload(LLC(c.decrypt(self.wepdata)))
    end
  end
end                    

class PrismHeader < Packet
  %( iwpriv wlan0 monitor 3 )
  @@name = "Prism header"
  @@fields_desc = [ LEIntField.new("msgcode",68),
                    LEIntField.new("len",144),
              StrFixedLenField.new("dev","",16),
                    LEIntField.new("hosttime_did",0),
                  LEShortField.new("hosttime_status",0),
                  LEShortField.new("hosttime_len",0),
                    LEIntField.new("hosttime",0),
                    LEIntField.new("mactime_did",0),
                  LEShortField.new("mactime_status",0),
                  LEShortField.new("mactime_len",0),
                    LEIntField.new("mactime",0),
                    LEIntField.new("channel_did",0),
                  LEShortField.new("channel_status",0),
                  LEShortField.new("channel_len",0),
                    LEIntField.new("channel",0),
                    LEIntField.new("rssi_did",0),
                  LEShortField.new("rssi_status",0),
                  LEShortField.new("rssi_len",0),
                    LEIntField.new("rssi",0),
                    LEIntField.new("sq_did",0),
                  LEShortField.new("sq_status",0),
                  LEShortField.new("sq_len",0),
                    LEIntField.new("sq",0),
                    LEIntField.new("signal_did",0),
                  LEShortField.new("signal_status",0),
                  LEShortField.new("signal_len",0),
              LESignedIntField.new("signal",0),
                    LEIntField.new("noise_did",0),
                  LEShortField.new("noise_status",0),
                  LEShortField.new("noise_len",0),
                    LEIntField.new("noise",0),
                    LEIntField.new("rate_did",0),
                  LEShortField.new("rate_status",0),
                  LEShortField.new("rate_len",0),
                    LEIntField.new("rate",0),
                    LEIntField.new("istx_did",0),
                  LEShortField.new("istx_status",0),
                  LEShortField.new("istx_len",0),
                    LEIntField.new("istx",0),
                    LEIntField.new("frmlen_did",0),
                  LEShortField.new("frmlen_status",0),
                  LEShortField.new("frmlen_len",0),
                    LEIntField.new("frmlen",0),
                    ]
end
