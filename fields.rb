class Field
  %(For more informations on how this work, please refer to
  http://www.secdev.org/projects/scapy/files/scapydoc.pdf
  chapter ``Adding a New Field'')
  @@is_list = false
  
  @@holds_packets = false
  
  def initialize(name, default, fmt="H")
    @name = name

    if "@=<>!".include?(fmt[0])
      @fmt = fmt
    else
      @fmt = "!"+fmt
    end

    @default = self.any2i(None,default)
    @size = struct.calcsize(self.fmt)
    @owners = []
  end

  def Field.is_list?
    @@is_list
  end
  
  def Field.holds_packets?
    @@holds_packets
  end

  def register_owner(cls)
    @owners << cls
  end

  def i2len(packet, x)
    %(Convert internal value to a length usable by a FieldLenField)
    return @size
  end
  
  def h2i(packet, x)
    %(Convert human value to internal value)
    return x
  end

  def i2h(packet, x)
    %(Convert internal value to human value)
    return x
  end

  def m2i(packet, x)
    %(Convert machine value to internal value)
    return x
  end

  def i2m(packet, x)
    %(Convert internal value to machine value)
    if x.nil?
      x = 0
    end
    return x
  end

  def any2i(packet, x)
    %(Try to understand the most input values possible and make an internal value from them)
    return h2i(packet, x)
  end

  def i2repr(packet, x)
    %(Convert internal value to a nice representation)
    if x.nil?
      x = 0
    end
    return i2h(packet, x).inspect
  end
  
  def add_field(packet, s, value)
    %(Add an internal value  to a string)
    return s + struct.pack(@fmt, i2m(packet, value))
  end

  def getfield(packet, s)
    %(Extract an internal value from a string)
    return  s[@size..-1], m2i(packet, struct.unpack(self.fmt, s[0, @size])[0])
  end

  def do_copy(x)
    if hasattr(x, "copy")
      return x.copy()
    elsif x.kind_of(Array)
      return x.clone
    else
      return x
    end
  end

  # Converted ",".join(x.__name__ for x in self.owners) to 
  def inspect
    return "<Field (%s).%s>" % [@owners.map{ |x| x.name }.join(','), self.name]
  end

  def copy
    return copy.deepcopy(self)
  end

  def random_value
    %(Return a volatile object whose value is both random and suitable for this field)
    fmtt = self.fmt[-1]
    if "BHIQ".include?(fmtt)
      return {"B" => RandByte, "H" => RandShort,"I" => RandInt, "Q" => RandLong}[fmtt] #()
    elsif fmtt == "s"
      if "0123456789".include?(@fmt[0])
        l = @fmt[0...-1].to_i
      else
        l = int(self.fmt[1...-1])
      end
      return RandBin(l)
    else
      warning("no random class for [%s] (fmt=%s)." % [self.name, self.fmt])
    end
  end 
end

class Emph
  @@fld = ""
  def initialize(fld)
    @fld = fld
  end

  def __getattr__(attribute)
    return getattr(self.fld, attribute)
  end
end

class ActionField
  def initialize(fld, action_method, *kargs)
    self._fld = fld
    self._action_method = action_method
    self._privdata = kargs
  end

  def any2i(pkt, val)
    #getattr(pkt, self._action_method)(val, self._fld, *self._privdata)
    pkt.send(self._action_method, val, self._fld, *self._privdata)
    
    #return getattr(self._fld, "any2i")(pkt, val)
    return send(self._fld, :any2i, pkt, val)
  end

  def __getattr__(attribute)
    return getattr(self._fld, attribute)
  end
end

class ConditionalField
  def initialize(fld, fldlst, cond)
    self.fld = fld
    self.fldlst = fldlst
    self.cond = cond
  end
  
  def _evalcond(pkt)
    if self.fldlist.kind_of?(Array) #type(self.fldlst) is list or type(self.fldlst) is tuple
      #res = map(lambda x,pkt=pkt:getattr(pkt,x), self.fldlst)
      # FIXME: this is wrong!!!
      res = @fldlst.map{ |x| pkt.send(x) }
    else
      res = getattr(pkt, self.fldlst)
    end
    return self.cond(res)
  end
  
  def getfield(pkt, s)
    if self._evalcond(pkt)
      return self.fld.getfield(pkt,s)
    else
      return s, nil
    end
  end

  def addfield(pkt, s, val)
    if self._evalcond(pkt)
      return self.fld.addfield(pkt,s,val)
    else
      return s
    end
  end

  # TODO: make me method_missing
  def __getattr__(attr)
    return getattr(self.fld, attr)
  end
end

class MACField < Field
  def initialize(name, default)
    Field.initialize(name, default, "6s")
  end
  
  def i2m(pkt, x)
    if x.nil?
      return "\0\0\0\0\0\0"
    end
    return mac2str(x)
  end
  
  def m2i(pkt, x)
    return str2mac(x)
  end
  
  def any2i(pkt, x)
    if x.kind_of?(String) and x.length == 6
      x = self.m2i(pkt, x)
    end
    return x
  end
  
  def i2repr(pkt, x)
    x = self.i2h(pkt, x)
    if conf.include?(self)
      x = conf.manufdb._resolve_MAC(x)
    end
    return x
  end
  def randval
    return RandMAC()
  end
end

class IPField < Field
  def initialize(name, default)
    Field.initialize(name, default, "4s")
  end

  def h2i(pkt, x)
    if x.kind_of?(String)
      begin
        inet_aton(x)
      rescue socket.error
        x = Net(x)
      end
    elsif x.kind_of(Array)
      x = map(Net, x)
    end
    return x
  end
      
=begin
    def resolve(x)
        if self in conf.resolve
            try
                ret = socket.gethostbyaddr(x)[0]
            except socket.herror
                pass
            else
                if ret
                    return ret
        return x
=end
  # Hah!!
  
  def i2m(pkt, x)
    return inet_aton(x)
  end

  def m2i(pkt, x)
    return inet_ntoa(x)
  end

  def any2i(pkt, x)
    return self.h2i(pkt,x)
  end
      
  def i2repr(pkt, x)
    return self.resolve(self.i2h(pkt, x))
  end

  def randval
    return RandIP.new()
  end
end

class SourceIPField < IPField
  def initialize(name, dstname)
    IPField.initialize(name, None)
    self.dstname = dstname
  end

  def i2m(pkt, x)
    if x.nil?
      iff, x, gw = conf.route.route(getattr(pkt,self.dstname))
    end
    return IPField.i2m(pkt, x)
  end

  def i2h(pkt, x)
    if x.nil?
      dst=getattr(pkt,self.dstname)
      if isinstance(dst,Gen)
        r = map(conf.route.route, dst)
        r.sort()
        if r[0] == r[-1]
          x=r[0][1]
        else
          warning("More than one possible route for %s"%repr(dst))
          return None
        end
      else
        iff,x,gw = conf.route.route(dst)
      end
    end
    return IPField.i2h(pkt, x)
  end
end

class ByteField < Field
  def initialize(name, default)
    Field.initialize(name, default, "B")
  end
end

class XByteField < ByteField
  def i2repr(pkt, x)
    if x.nil?
      x = 0
    end
    return lhex(self.i2h(pkt, x))
  end
end

class X3BytesField < XByteField
  def initialize(name, default)
    Field.initialize(name, default, "!I")
  end

  def addfield(pkt, s, val)
    return s + struct.pack(self.fmt, self.i2m(pkt,val))[1:4]
  end

  def getfield(pkt, s)
    return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00"+s[:3])[0])
  end
end

class ShortField < Field
  def initialize(name, default)
    Field.initialize(name, default, "H")
  end
end

class LEShortField < Field
  def initialize(name, default)
    Field.initialize(name, default, "<H")
  end
end

class XShortField < ShortField
  def i2repr(pkt, x)
    if x.nil?
      x = 0
    end
    return lhex(self.i2h(pkt, x))
  end
end

class IntField < Field
  def initialize(name, default)
    Field.initialize(name, default, "I")
  end
end

class SignedIntField < Field
  def initialize(name, default)
    Field.initialize(name, default, "i")
  end
end

class LEIntField < Field
  def initialize(name, default)
    Field.initialize(name, default, "<I")
  end
end

class LESignedIntField < Field
  def initialize(name, default)
    Field.initialize(name, default, "<i")
  end
end

class XIntField < IntField
  def i2repr(pkt, x)
    if x.nil?
      x = 0
    end
    return lhex(self.i2h(pkt, x))
  end
end

class LongField < Field
  def initialize(name, default)
    Field.initialize(name, default, "Q")
  end
end

class XLongField < LongField
  def i2repr(pkt, x)
    if x.nil?
      x = 0
    end
    return lhex(self.i2h(pkt, x))
  end
end

class StrField < Field
  def initialize(name, default, fmt="H", remain=0, shift=0)
    Field.initialize(self,name,default,fmt)
    self.remain = remain
    self.shift = shift
  end

  def i2len(pkt, i)
    return len(i)+self.shift
  end

  def i2m(pkt, x)
    if x.nil?
      x = ""
    end
    return x
  end

  def addfield(pkt, s, val)
    return s+self.i2m(pkt, val)
  end

  def getfield(pkt, s)
    if self.remain == 0
      return "",self.m2i(pkt, s)
    else
      return s[-self.remain:],self.m2i(pkt, s[:-self.remain])
    end
  end

  def randval
    return RandBin.new(RandNum.new(0,1200))
  end
end

class PacketField < StrField
  @@holds_packets=true

  def initialize(name, default, cls, remain=0, shift=0)
    StrField.initialize(name, default, remain=remain, shift=shift)
    self.cls = cls
  end

  def i2m(pkt, i)
    return str(i)
  end

  def m2i(pkt, m)
    return self.cls(m)
  end

  def getfield(pkt, s)
    i = self.m2i(pkt, s)
    remain = ""
    if i.haslayer(Padding)
      r = i.getlayer(Padding)
      del(r.underlayer.payload)
      remain = r.load
    end

    return remain,i
  end
end

class PacketLenField < PacketField
  @@holds_packets=true

  def initialize(name, default, cls, fld, shift=0)
    PacketField.initialize(name, default, cls, shift=shift)
    self.fld = fld
  end

  def getfield(pkt, s)
    l = getattr(pkt, self.fld)
    l -= self.shift
    i = self.m2i(pkt, s[:l])
    return s[l:],i
  end
end

class PacketListField < PacketLenField
  @@islist = true
  @@holds_packets= true

  def do_copy(x)
    return map(lambda p:p.copy(), x)
  end

  def getfield(pkt, s)
    l = getattr(pkt, self.fld)
    l -= self.shift
    lst = []
    remain = s
    while l > 0 and remain.length > 0
      l -= 1
      p = self.m2i(pkt,remain)
      if p.include?(Padding)
        pad = p[Padding]
        remain = pad.load
        del(pad.underlayer.payload)
      else
        remain = ""
      end
      lst.append(p)
    end
    return remain,lst
  end

  def addfield(pkt, s, val)
    return s+"".join(map(str, val))
  end
end

class StrFixedLenField < StrField
  def initialize(name, default, length, shift=0)
    StrField.initialize(name, default, shift=shift)
    self.length = length
  end

  def getfield(pkt, s)
    return s[self.length:], self.m2i(pkt,s[:self.length])
  end

  def addfield(pkt, s, val)
    return s+struct.pack("%is"%self.length,self.i2m(pkt, val))
  end

  def randval
    return RandBin.new(self.length)
  end
end

=begin
class NetBIOSNameField < StrFixedLenField
    def initialize(name, default, length=31, shift=0)
        StrFixedLenField.initialize(name, default, length, shift=shift)
    def i2m(pkt, x)
        if x.nil?
            x = ""
        x += " "*(self.length/2)
        x = x[:(self.length/2)]
        x = "".join(map(lambda x: chr(0x41+(ord(x)>>4))+chr(0x41+(ord(x)&0xf)), x))
        x = " "+x
        return x
    def m2i(pkt, x)
        x = x.strip("\x00").strip(" ")
        return "".join(map(lambda x,y: chr((((ord(x)-1)&0xf)<<4)+((ord(y)-1)&0xf)), x[::2],x[1::2]))
=end

class StrLenField < StrField
  def initialize(name, default, fld, shift=0)
    StrField.initialize(name, default, shift=shift)
    self.fld = fld
  end

  def getfield(pkt, s)
    l = getattr(pkt, self.fld)
    l -= self.shift
    return s[l:], self.m2i(pkt,s[:l])
  end
end

class FieldListField < Field
  @@islist = true

  def initialize(name, default, cls, fld, shift=0)
    Field.initialize(name, default)
    self.cls = cls
    self.fld = fld
    self.shift=shift
  end

  def i2len(pkt, val)
    if val.nil?
      return self.shift
    else
      return len(val)+self.shift
    end
  end

  def i2m(pkt, val)
    if val.nil?
      val = []
    end
    return val
  end

  def addfield(pkt, s, val)
    val = self.i2m(pkt, val)
    for v in val
      s = self.cls.addfield(pkt, s, v)
    end
    return s
  end

  def getfield(pkt, s)
    l = getattr(pkt, self.fld)        
    # add the shift from the length field
    f = pkt.get_field(self.fld)
    l -= self.shift
    val = []
    for i in range(l)
      s,v = self.cls.getfield(pkt, s)
      val.append(v)
    end

    return s, val
  end
end

class FieldLenField < Field
  def initialize(name, default, fld, fmt = "H")
    Field.initialize(name, default, fmt)
    self.fld = fld
  end

  def i2m(pkt, x)
    if x.nil?
      f = pkt.get_field(self.fld)
      x = f.i2len(pkt,pkt.getfieldval(self.fld))
    end

    return x
  end
end

class StrNullField < StrField
  def addfield(pkt, s, val)
    return s+self.i2m(pkt, val)+"\x00"
  end

  def getfield(pkt, s)
    l = s.find("\x00")
    if l < 0
      #XXX \x00 not found
      return "",s
    end

    return s[l+1:],self.m2i(pkt, s[:l])
  end

  def randval
    return RandTermString(RandNum(0,1200),"\x00")
  end
end

class StrStopField < StrField
  def initialize(name, default, stop, additionnal=0)
    Field.initialize(name, default)
    self.stop=stop
    self.additionnal=additionnal
  end

  def getfield(pkt, s)
    l = s.find(self.stop)
    if l < 0
      return "",s
      # raise Scapy_Exception,"StrStopField: stop value [%s] not found" %stop
    end
    l += len(self.stop)+self.additionnal
    return s[l:],s[:l]
  end

  def randval
    return RandTermString(RandNum(0,1200),self.stop)
  end
end

class LenField < Field
  def i2m(pkt, x)
    if x.nil?
      x = len(pkt.payload)
    end
    return x
  end
end

class BCDFloatField < Field
  def i2m(pkt, x)
    return int(256*x)
  end

  def m2i(pkt, x)
    return x/256.0
  end
end

class BitField < Field
  def initialize(name, default, size)
    Field.initialize(name, default)
    self.size = size
  end

  def addfield(pkt, s, val)
    if val.nil?
      val = 0
    end

    if type(s) is tuple
      s,bitsdone,v = s
    else
      bitsdone = 0
      v = 0
    end

    v <<= self.size
    v |= val & ((1L<<self.size) - 1)
    bitsdone += self.size
    while bitsdone >= 8
      bitsdone -= 8
      s = s+struct.pack("!B", v >> bitsdone)
      v &= (1L<<bitsdone)-1
    end

    if bitsdone
      return s,bitsdone,v
    else
      return s
    end
  end

  def getfield(pkt, s)
    if type(s) is tuple
      s,bn = s
    else
      bn = 0
    end

    # we don't want to process all the string
    nb_bytes = (self.size+bn-1)/8 + 1
    w = s[:nb_bytes]

    # split the substring byte by byte
    bytes = struct.unpack('!%dB' % nb_bytes , w)

    b = 0L
    for c in range(nb_bytes)
      b |= long(bytes[c]) << (nb_bytes-c-1)*8
    end

    # get rid of high order bits
    b &= (1L << (nb_bytes*8-bn)) - 1

    # remove low order bits
    b = b >> (nb_bytes*8 - self.size - bn)

    bn += self.size
    s = s[bn/8:]
    bn = bn%8
    if bn
      return (s,bn),b
    else
      return s,b
    end
  end

  def randval
    return RandNum(0,2**self.size-1)
  end
end

class XBitField < BitField
  def i2repr(pkt, x)
    return lhex(self.i2h(pkt,x))
  end
end

class EnumField < Field
  def initialize(name, default, enum, fmt = "H")
    i2s = self.i2s = {}
    s2i = self.s2i = {}
    if type(enum) is list
      keys = xrange(len(enum))
    else
      keys = enum.keys()
    end

    if filter(lambda x: type(x) is str, keys)
      i2s,s2i = s2i,i2s
    end

    for k in keys
      i2s[k] = enum[k]
      s2i[enum[k]] = k
    end

    Field.initialize(name, default, fmt)
  end
      
  def any2i_one(pkt, x)
    if type(x) is str
      x = self.s2i[x]
    end
    return x
  end

  def i2repr_one(pkt, x)
    if self not in conf.noenum and x in self.i2s
      return self.i2s[x]
    end
    return repr(x)
  end
    
  def any2i(pkt, x)
    if type(x) is list
      return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)
    else
      return self.any2i_one(pkt,x)        
    end
  end
        
  def i2repr(pkt, x)
    if type(x) is list
      return map(lambda z,pkt = pkt:self.i2repr_one(pkt,z), x)
    else
      return self.i2repr_one(pkt,x)
    end
  end
end

class CharEnumField < EnumField
  def initialize(name, default, enum, fmt = "1s")
    EnumField.initialize(name, default, enum, fmt)
    k = self.i2s.keys()
    if k and len(k[0]) != 1
      self.i2s,self.s2i = self.s2i,self.i2s
    end
  end

  def any2i_one(pkt, x)
    if len(x) != 1
      x = self.s2i[x]
    end

    return x
  end
end

=begin
TODO: pseudo-multiple inheritance needs to be done... probably just include one
class BitEnumField < BitField, EnumField
    def initialize(name, default, size, enum)
        EnumField.initialize(name, default, enum)
        self.size = size
    def any2i(pkt, x)
        return EnumField.any2i(pkt, x)
    def i2repr(pkt, x)
        return EnumField.i2repr(pkt, x)
=end

class ShortEnumField < EnumField
  def initialize(name, default, enum)
    EnumField.initialize(name, default, enum, "H")
  end
end

class LEShortEnumField < EnumField
  def initialize(name, default, enum)
    EnumField.initialize(name, default, enum, "<H")
  end
end

class ByteEnumField < EnumField
  def initialize(name, default, enum)
    EnumField.initialize(name, default, enum, "B")
  end
end

class IntEnumField < EnumField
  def initialize(name, default, enum)
    EnumField.initialize(name, default, enum, "I")
  end
end

class LEIntEnumField < EnumField
  def initialize(name, default, enum)
    EnumField.initialize(name, default, enum, "<I")
  end
end

class XShortEnumField < ShortEnumField
  def i2repr_one(pkt, x)
    if self not in conf.noenum and x in self.i2s
      return self.i2s[x]
    end
    return lhex(x)
  end
end

# Little endian long field
class LELongField < Field
  def initialize(name, default)
    Field.initialize(name, default, "<Q")
  end
end

# Little endian fixed length field
class LEFieldLenField < FieldLenField
  def initialize(name, default, fld, fmt = "<H")
    FieldLenField.initialize(name, default, fld=fld, fmt=fmt)
  end
end

class FlagsField < BitField
  def initialize(name, default, size, names)
    BitField.initialize(name, default, size)
    self.multi = type(names) is list
    if self.multi
      self.names = map(lambda x:[x], names)
    else
      self.names = names
    end
  end          

  def any2i(pkt, x)
    if type(x) is str
      if self.multi
        x = map(lambda y:[y], x.split("+"))
      end

      y = 0
      for i in x
        y |= 1 << self.names.index(i)
      end

      x = y
    end

    return x
  end
      
  def i2repr(pkt, x)
    if self.multi
      r = []
    else
      r = ""
    end
    i=0
    while x
      if x & 1
        r += self.names[i]
      end
      i += 1
      x >>= 1
    end

    if self.multi
      r = "+".join(r)
    end
    return r
  end
end            

class IPoptionsField < StrField
  def i2m(pkt, x)
    return x+"\x00"*(3-((len(x)+3)%4))
  end

  def getfield(pkt, s)
    opsz = (pkt.ihl-5)*4
    if opsz < 0
      warning("bad ihl (%i). Assuming ihl=5"%pkt.ihl)
      opsz = 0
    end
    return s[opsz:],s[:opsz]
  end

  def randval
    return RandBin(RandNum(0,39))
  end
end

=begin
TODO: me, but not for now

TCPOptions = [
              { 0 => ["EOL", None],
                1 => ["NOP", None],
                2 => ["MSS", "!H"],
                3 => ["WScale", "!B"],
                4 => ["SAckOK", None],
                5 => ["SAck", "!"],
                8 => ["Timestamp", "!II"],
                14 => ["AltChkSum", "!BH"],
                15 => ["AltChkSumOpt", None]
                },
              { "EOL"=>0,
                "NOP"=>1,
                "MSS"=>2,
                "WScale"=>3,
                "SAckOK"=>4,
                "SAck"=>5,
                "Timestamp"=>8,
                "AltChkSum"=>14,
                "AltChkSumOpt"=>15,
                } ]

class TCPOptionsField < StrField
    islist=1
    def getfield(pkt, s)
        opsz = (pkt.dataofs-5)*4
        if opsz < 0
            warning("bad dataofs (%i). Assuming dataofs=5"%pkt.dataofs)
            opsz = 0
        return s[opsz:],self.m2i(pkt,s[:opsz])
    def m2i(pkt, x)
        opt = []
        while x
            onum = ord(x[0])
            if onum == 0
                opt.append(("EOL",None))
                x=x[1:]
                break
            if onum == 1
                opt.append(("NOP",None))
                x=x[1:]
                continue
            olen = ord(x[1])
            if olen < 2
                warning("Malformed TCP option (announced length is %i)" % olen)
                olen = 2
            oval = x[2:olen]
            if TCPOptions[0].has_key(onum)
                oname, ofmt = TCPOptions[0][onum]
                if onum == 5: #SAck
                    ofmt += "%iI" % (len(oval)/4)
                if ofmt and struct.calcsize(ofmt) == len(oval)
                    oval = struct.unpack(ofmt, oval)
                    if len(oval) == 1
                        oval = oval[0]
                opt.append((oname, oval))
            else
                opt.append((onum, oval))
            x = x[olen:]
        return opt
    
    def i2m(pkt, x)
        opt = ""
        for oname,oval in x
            if type(oname) is str
                if oname == "NOP"
                    opt += "\x01"
                    continue
                elif oname == "EOL"
                    opt += "\x00"
                    continue
                elif TCPOptions[1].has_key(oname)
                    onum = TCPOptions[1][oname]
                    ofmt = TCPOptions[0][onum][1]
                    if onum == 5: #SAck
                        ofmt += "%iI" % len(oval)
                    if ofmt is not None
                        if type(oval) is not tuple
                            oval = (oval,)
                        oval = struct.pack(ofmt, *oval)
                else
                    warning("option [%s] unknown. Skipped."%oname)
                    continue
            else
                onum = oname
                if type(oval) is not str
                    warning("option [%i] is not string."%onum)
                    continue
            opt += chr(onum)+chr(2+len(oval))+oval
        return opt+"\x00"*(3-((len(opt)+3)%4))
    def randval
        return [] # XXX
    

class DNSStrField < StrField
    def i2m(pkt, x)
        x = x.split(".")
        x = map(lambda y: chr(len(y))+y, x)
        x = "".join(x)
        if x[-1] != "\x00"
            x += "\x00"
        return x
    def getfield(pkt, s)
        n = ""
        while 1
            l = ord(s[0])
            s = s[1:]
            if not l
                break
            if l & 0xc0
                raise Scapy_Exception("DNS message can't be compressed at this point!")
            else
                n += s[:l]+"."
                s = s[l:]
        return s, n


class DNSRRCountField < ShortField
    holds_packets=1
    def initialize(name, default, rr)
        ShortField.initialize(name, default)
        self.rr = rr
    def _countRR(pkt)
        x = getattr(pkt,self.rr)
        i = 0
        while isinstance(x, DNSRR) or isinstance(x, DNSQR)
            x = x.payload
            i += 1
        return i
        
    def i2m(pkt, x)
        if x.nil?
            x = self._countRR(pkt)
        return x
    def i2h(pkt, x)
        if x.nil?
            x = self._countRR(pkt)
        return x
    

def DNSgetstr(s,p)
    name = ""
    q = 0
    jpath = [p]
    while 1
        if p >= len(s)
            warning("DNS RR prematured end (ofs=%i, len=%i)"%(p,len(s)))
            break
        l = ord(s[p])
        p += 1
        if l & 0xc0
            if not q
                q = p+1
            if p >= len(s)
                warning("DNS incomplete jump token at (ofs=%i)" % p)
                break
            p = ((l & 0x3f) << 8) + ord(s[p]) - 12
            if p in jpath
                warning("DNS decompression loop detected")
                break
            jpath.append(p)
            continue
        elif l > 0
            name += s[p:p+l]+"."
            p += l
            continue
        break
    if q
        p = q
    return name,p
        

class DNSRRField < StrField
    holds_packets=1
    def initialize(name, countfld, passon=1)
        StrField.initialize(name, None)
        self.countfld = countfld
        self.passon = passon
    def i2m(pkt, x)
        if x.nil?
            return ""
        return str(x)
    def decodeRR(name, s, p)
        ret = s[p:p+10]
        type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
        p += 10
        rr = DNSRR("\x00"+ret+s[p:p+rdlen])
        if rr.type in [2, 3, 4, 5]
            rr.rdata = DNSgetstr(s,p)[0]
        del(rr.rdlen)
        
        p += rdlen
        
        rr.rrname = name
        return rr,p
    def getfield(pkt, s)
        if type(s) is tuple 
            s,p = s
        else
            p = 0
        ret = None
        c = getattr(pkt, self.countfld)
        if c > len(s)
            warning("wrong value: DNS.%s=%i" % (self.countfld,c))
            return s,""
        while c
            c -= 1
            name,p = DNSgetstr(s,p)
            rr,p = self.decodeRR(name, s, p)
            if ret.nil?
                ret = rr
            else
                ret.add_payload(rr)
        if self.passon
            return (s,p),ret
        else
            return s[p:],ret
            
            
class DNSQRField < DNSRRField
    holds_packets=1
    def decodeRR(name, s, p)
        ret = s[p:p+4]
        p += 4
        rr = DNSQR("\x00"+ret)
        rr.qname = name
        return rr,p        

class RDataField < StrLenField
    def m2i(pkt, s)
        family = None
        if pkt.type == 1
            family = socket.AF_INET
        elif pkt.type == 28
            family = socket.AF_INET6
        elif pkt.type == 12
            s = DNSgetstr(s, 0)[0]
        if family is not None:    
            s = inet_ntop(family, s)
        return s
    def i2m(pkt, s)
        if pkt.type == 1
            if s
                s = inet_aton(s)
        elif pkt.type == 28
            if s
                s = inet_pton(socket.AF_INET6, s)
        elif pkt.type in [2,3,4,5]
            s = "".join(map(lambda x: chr(len(x))+x, s.split(".")))
            if ord(s[-1])
                s += "\x00"
        return s

class RDLenField < Field
    def initialize(name)
        Field.initialize(name, None, "H")
    def i2m(pkt, x)
        if x.nil?
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
    def i2h(pkt, x)
        if x.nil?
            rdataf = pkt.get_field("rdata")
            x = len(rdataf.i2m(pkt, pkt.rdata))
        return x
  
# seconds between 01-01-1900 and 01-01-1970
ntp_basetime = 2208988800

class TimeStampField < BitField
    def initialize(name, default, size)
        BitField.initialize(name, default, size)
        self.size  = size
    def getfield(pkt, s)
        s,timestamp = BitField.getfield(pkt, s)

        if timestamp
            # timestamp is a 64 bits field 
            #  + first 32 bits : number of seconds since 1900
            #  + last 32 bits  : fraction part
            timestamp >>= 32
            timestamp -= ntp_basetime
            
            from time import gmtime, strftime
            b = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(timestamp))
        else
            b = 'None'
        
        return s, b
    def addfield(pkt, s, val)
        t = -1
        if type(val) is str
            from time import strptime, mktime
            t = int(mktime(strptime(val))) + ntp_basetime + 3600
        else
            if val == -1
                from time import time
                t = int(time()) + ntp_basetime
            else
                t = val
        t <<= 32
        return BitField.addfield(self,pkt,s, t)
=end  

class FloatField < BitField
  def getfield(pkt, s)
    s,b = BitField.getfield(pkt, s)

    # fraction point between bits 15 and 16.
    sec = b >> 16
    frac = b & (1L << (32+1)) - 1
    frac /= 65536.0
    b = sec+frac
    return s,b    
  end
end
