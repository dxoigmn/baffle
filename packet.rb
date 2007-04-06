class Generator

end


class Packet < Generator
  # huh? __metaclass__ = Packet_metaclass
  @@name=nil

  @@fields_desc = []

  @@aliastypes = []
  @@overload_fields = {}

  @@underlayer = nil

  @@payload_guess = []
  @@initialized = 0
  @@show_indent=1

  def Packet.from_hexcap(cls)
    return cls(import_hexcap())
  end

  def initialize(_packet="", post_transform=nil, _internal=false, _underlayer=nil, *fields)
    @time  = time.time()
    if @name.nil?
      @name = self.__class__.__name__
    end
    @aliastypes = [ self.class ] + @@aliastypes
    @default_fields = {}
    @overloaded_fields = {}
    @fields={}
    @fieldtype={}
    @packetfields=[]
    
    # huh?
    @__dict__["payload"] = NoPayload()
    
    init_fields()
    @underlayer = _underlayer
    @initialized = true
    
    if _packet
      dissect(_packet)
      if !_internal
        dissection_done()
      end
    end

    fields.keys.each do |f|
      self.fields[f] = self.get_field(f).any2i(self,fields[f])
    end

    if post_transform.kind_of?(Array)
      self.post_transforms = post_transform
    elsif post_transform.nil?
      self.post_transforms = []
    else
      self.post_transforms = [post_transform]
    end
  end
    
  def init_fields()
    do_init_fields(@@fields_desc)
  end

  def do_init_fields(field_list)
    field_list.each do |field|
      @default_fields[field.name] = field.default
      @fieldtype[field.name] = field
      
      if field.holds_packets?
        @packetfields << field
      end
    end
  end
            
  def dissection_done(packet)
    %(DEV: will be called after a dissection is completed)
    post_dissection(packet)
    payload.dissection_done(packet)
  end

  def post_dissection(packet)
    %(DEV: is called after the dissection of the whole packet)
  end

  def get_field(field)
    %(DEV: returns the field instance from the name of the field)
    return @fieldtype[field]
  end
  
  def initialized?
    @initialized
  end
        
  def add_payload(payload)
    if payload.nil?
      return
    elsif !@payload.kind_of?(NoPayload)
      @payload.add_payload(payload)
    else
      if @payload.kind_of?(Packet)
        @__dict__["payload"] = payload
        @payload.add_underlayer(self)
        @aliastypes.each do |type|
          if @payload.overload_fields.has_key?(type)
            @overloaded_fields = payload.overload_fields[type]
            break
          end
        end

      elsif payload.kind_of?(String)
        @__dict__["payload"] = Raw(:load => payload)
      else
        raise TypeError("payload must be either 'Packet' or 'str', not [%s]" % repr(payload))
      end
    end
  end

  def remove_payload()
    @payload.remove_underlayer(self)
    @__dict__["payload"] = NoPayload.new
    @overloaded_fields = {}
  end
      
  def add_underlayer(underlayer)
    @underlayer = underlayer
  end
      
  def remove_underlayer(other)
    @underlayer = nil
  end
  
  def copy
    %(Returns a deep copy of the instance.)
    # huh?
    clone = self.class.new()
    clone.fields = @fields.clone
    clone.fields.each do |k|
      clone.fields[k]=self.get_field(k).do_copy(clone.fields[k])
    end
    
    clone.default_fields = @default_fields.clone
    clone.overloaded_fields = @overloaded_fields.clone
    clone.overload_fields = @overload_fields.clone
    clone.underlayer= @underlayer
    clone.post_transforms= @post_transforms.clone
    
    clone.__dict__["payload"] = @payload.clone
    clone.payload.add_underlayer(clone)
    
    return clone
  end

  def get_field_value(attribute)
    (@fields + @overloaded_fields + @default_fields).each do |field|
      if field.has_key?(attribute)
        return field[attribute]
      end
    end
    return @payload.get_field_value(attribute)
  end

  def getfield_and_value(attribute)
    (@fields + @overloaded_fields + @default_fields).each do |field|
      if field.has_key(attribute)
        return get_field(attribute), field[attribute]
      end
    end
    return @payload.getfield_and_value(attribute)
  end

  # TODO: these three should be condensed into method_missing
  def __getattr__(attribute)
    if initialized?
      field, v = getfield_and_value(attribute)
      if field
        return field.i2h(v)
      end
      return v
    end
    raise AttributeError(attribute)
  end

  def __setattr__(attribute, value)
    if initialized?
      if @default_fields.has_key?(attribute)
        field = self.get_field(attribute)
        if field.nil?
          any2i = lambda { |x, y| y }
        else
          any2i = field.any2i
        end
        @fields[attribute] = any2i(value)
      elsif attr == "payload"
        remove_payload()
        add_payload(value)
      else
        @__dict__[attribute] = value
      end
    else
      @__dict__[attribute] = value
    end
  end

  def __delattr__(attribute)
    if initialized?
      if @fields.has_key?(attribute)
        del(@fields[attribute])
        return
      elsif @default_fields.has_key(attribute)
        return
      elsif attribute == "payload"
        remove_payload()
        return
      end
    end
    if @__dict__.has_key(attribute)
      del(@__dict__[attribute])
    else
      raise AttributeError(attribute)
    end
  end
  
  # huh? __repr__ = inspect? no clue, but it felt right
  def inspect
    s = ""
    ct = conf.color_theme
    @fields_desc.each do |field|
      if fields.member?(field.name)
        value = field.i2repr(@fields[field.name])
      elsif @overloaded_fields.member?(field.name)
        value =  field.i2repr(@overloaded_fields[field.name])
      else
        continue
      end
      
      if field.kind_of?(Emph)
        ncol = ct.emph_field_name
        vcol = ct.emph_field_value
      else
        ncol = ct.field_name
        vcol = ct.field_value
      end

      s += " %s%s%s" % [ncol(field.name),
                        ct.punct("="),
                        vcol(value)]
    end

    return "%s%s %s %s%s%s"% [ct.punct("<"),
                              ct.layer_name(self.class.name),
                              s,
                              ct.punct("|"),
                              repr(@payload),
                              ct.punct(">")]
  end

  # __str__ should be to_s, right?
  def to_s
    return self.__iter__().next().build()
  end

  # __div__
  def /(other)
    if other.kind_of?(Packet)
      cloneA = self.copy()
      cloneB = other.copy()
      cloneA.add_payload(cloneB)
      return cloneA
    elsif other.kind_of?(String)
      return self/Raw(:load =>other)
    else
      return other.__rdiv__(self)
    end
  end
  
  # TODO: This should probably be dealt with using coerce or something
  def __rdiv__(other)
    if other.kind_of?(String)
      return Raw(:load => other)/self
    else
      raise TypeError
    end
  end

  def *(other)
    if other.kind_of?(Integer)
      return [self] * other
    else
      raise TypeError
    end
  end

  # TODO: again should use coerce
  def __rmul__(other)
    return self * other
  end
    
  def length
    to_s.length
  end

  def do_build
    p=""
    @fields_desc.each do |field|
      p = field.add_field(p, self.get_field_value(field.name))
    end
    return p
  end

  def post_build(packet, payload)
    %(DEV: called right after the current layer is build.)
    return packet + payload
  end

  def build_payload
    return @payload.build(:internal => true)
  end

  # TODO: deal with named parameter the ruby way (i.e. with a hash of parameters)
  def build(internal = false)
    packet = do_build

    @post_transforms.each do |transform|
      packet = transform(packet)
    end
    payload = build_payload

    begin
      p = post_build(packet, payload)
    rescue TypeError
      log_runtime.error("API changed! post_build() now takes 2 arguments. Compatibility is only assured for a short transition time")
      p = post_build(packet + payload)
    end

    if !internal
      pad = @payload.getlayer(Padding) 
      if pad: 
        p += pad.build()
      end
    end
    return p
  end

  def extract_padding(s)
    %(DEV: to be overloaded to extract current layer's padding. Return a couple of strings (actual layer, padding))
    return s, nil
  end

  def post_dissect(s)
    %(DEV: is called right after the current layer has been dissected)
    return s
  end

  def pre_dissect(s)
    %(DEV: is called right before the current layer is dissected)
    return s
  end

  def do_dissect(s)
    field_list = @fields_desc.clone
    field_list.reverse!

    while s and !field_list.empty?
      field = field_list.pop()
      s, field_value = field.getfield(s)
      @fields[field.name] = field_value
    end
    return s
  end

  # TODO: clean this up
  def do_dissect_payload(s)
    if s
      cls = guess_payload_class(s)
      begin
        p = cls(s, :_internal => true, :_underlayer => self)
      rescue KeyboardInterrupt
        raise
      rescue
        if conf.debug_dissector
          if isinstance(cls,type) and issubclass(cls,Packet)
            log_runtime.error("%s dissector failed" % cls.name)
          else
            log_runtime.error("%s.guess_payload_class() returned [%s]" % [self.class.name, cls.inspect])
          end
          if cls
            raise
          end
        end
        p = Raw(s, _internal=1, _underlayer=self)
      end
      self.add_payload(p)
    end
  end

  def dissect(s)
    s = self.pre_dissect(s)

    s = self.do_dissect(s)

    s = self.post_dissect(s)

    payload, padding = extract_padding(s)
    do_dissect_payload(payload)
    if padding and conf.padding
      add_payload(Padding(padding))
    end
  end

  # TODO: clean me up
  def guess_payload_class(payload)
    %(DEV: Guesses the next payload class from layer bonds. Can be overloaded to use a different mechanism.)
    for t in @aliastypes
      for fvalue, cls in t.payload_guess
        ok = 1
        fvalue.keys.each do |key|
          if !hasattr(key) or fvalue[key] != self.get_field_value(key)
            ok = 0
            break
          end
        end
        if ok
          return cls
        end
      end
    end
    return default_payload_class(payload)
  end

  def default_payload_class(payload)
    %(DEV: Returns the default payload class if nothing has been found by the guess_payload_class() method.)
    return Raw
  end

  def hide_defaults
    %(Removes fields' values that are the same as default values.)
    @fields.keys.each do |key|
      if @default_fields.has_key?(key)
        if @default_fields[key] == @fields[key]
          @fields.delete(k)
        end
      end
    end
    @payload.hide_defaults()
  end

=begin
TODO: DO ME in a reasonable manner!!!
    def __iter__(self)
        def loop(todo, done, self=self)
            if todo
                eltname = todo.pop()
                elt = self.get_field_value(eltname)
                if !isinstance(elt, Gen)
                    if self.get_field(eltname).islist
                        elt = SetGen([elt])
                    else
                        elt = SetGen(elt)
                for e in elt
                    done[eltname]=e
                    for x in loop(todo[:], done)
                        yield x
            else
                if isinstance(self.payload,NoPayload)
                    payloads = [nil]
                else
                    payloads = self.payload
                for payl in payloads
                    done2=done.copy()
                    for k in done2
                        if isinstance(done2[k], VolatileValue)
                            done2[k] = done2[k]._fix()
                    packet = self.__class__()
                    packet.fields = done2
                    packet.time = self.time
                    packet.underlayer = self.underlayer
                    packet.overload_fields = self.overload_fields.copy()
                    packet.post_transforms = self.post_transforms
                    if payl is nil
                        yield packet
                    else
                        yield packet/payl
        todo = map(lambda (x,y):x, filter(lambda (x,y):isinstance(y,VolatileValue), self.default_fields.items()))
        todo += map(lambda (x,y):x, filter(lambda (x,y):isinstance(y,VolatileValue), self.overloaded_fields.items()))
        todo += self.fields.keys()
        return loop(map(lambda x:str(x), todo), {})
      end
=end
  # hah!

  def >(other)
    %(True if other is an answer from self (self ==> other).)
    if other.kind_of?(Packet)
      return other < self
    elsif other.kind_of?(String)
      return true
    else
      raise TypeError(other)
    end
  end

  def <(other)
    %(True if self is an answer from other (other ==> self).)
    if other.kind_of?(Packet)
      return self.answers(other)
    elsif other.kind_of?(String)
      return true
    else
      raise TypeError(other)
    end
  end

  def ==(other)
    if !other.kind_of?(self.class)
      return false
    end
    @fields_desc.each do |field|
      # TODO: check me!
      if !other.fields_desc.include?(field)
        return false
      end
      if self.get_field_value(f.name) != other.get_field_value(f.name)
        return false
      end
    end
    return self.payload == other.payload
  end

  def hashret
    %(DEV: returns a string that has the same value for a request and its answer.)
    return @payload.hashret()
  end

  def answers(other)
    %(DEV: true if self is an answer from other)
    if other.class == self.class
      return @payload.answers(other.payload)
    end
    return false
  end

  def haslayer(cls)
    %(true if self has a layer that is an instance of cls. Superseded by "cls in self" syntax.)
    if self.class == cls or self.class.name == cls
      return true
    end

    @packetfields.each do |field|
      fvalue_gen = get_field_value(field.name)
      if fvalue_gen.nil?
        continue
      end
      if !field.islist
        fvalue_gen = SetGen(fvalue_gen, :_iterpacket => 0)
      end
      fvalue_gen.each do |fvalue|
        if fvalue.kind_of?(Packet)
          ret = fvalue.haslayer(cls)
          if ret
            return ret
          end
        end
      end
    end
    return self.payload.haslayer(cls)
  end

  def getlayer(cls, nb=1, _track=nil)
    %(Return the nb^th layer that is an instance of cls.)
    if cls.kind_of?(String) and cls.member?(".")
      ccls, fld = cls.split(".",1)
    else
      ccls, fld = cls, nil
    end

    if self.class == cls or self.class.name == ccls
      if nb == 1
        if fld.nil?
          return self
        else
          return self.get_field_value(fld)
        end
      else
        nb -=1
      end
    end
    @packetfields.each do |field|
      fvalue_gen = self.get_field_value(field.name)
      if fvalue_gen.nil?
        continue
      end
      if !field.islist
        fvalue_gen = SetGen(fvalue_gen,_iterpacket=0)
      end
      fvalue_gen.each do |fvalue|
        if fvalue.kind_of?(Packet)
          track=[]
          ret = fvalue.getlayer(cls, nb, :_track => track)
          if ret
            return ret
          end
          nb = track[0]
        end
      end
    end
    return self.payload.getlayer(cls,nb,_track=_track)
  end

  # __getitem__
  def [](cls)
    if cls.kind_of?(Range)
      if cls.stop
        ret = self.getlayer(cls.start, cls.stop)
      else
        ret = self.getlayer(cls.start)
      end
      if ret.nil? and cls.step
        ret = cls.step
      end
      return ret
    else
      return self.getlayer(cls)
    end
  end

  def member?(cls)
    %("cls in self" returns true if self has a layer which is an instance of cls.)
    return haslayer(cls)
  end 

  def show(indent=3, lvl="", label_lvl="")
    %(Prints a hierarchical view of the packet. "indent" gives the size of indentation for each layer.)
    ct = conf.color_theme
    print "%s%s %s %s" % [label_lvl,
                          ct.punct("###["),
                          ct.layer_name(self.name),
                          ct.punct("]###")]
    @fields_desc.each do |f|
      if f.kind_of?(Emph)
        ncol = ct.emph_field_name
        vcol = ct.emph_field_value
      else
        ncol = ct.field_name
        vcol = ct.field_value
      end
      fvalue = get_field_value(f.name)

      if fvalue.kind_of?(Packet) or (f.islist and f.holds_packets)
        print "%s  \\%-10s\\" % [label_lvl+lvl, ncol(f.name)]
        fvalue_gen = SetGen(fvalue,_iterpacket=0)
        fvalue_gen.each do |fvalue|
          fvalue.show(indent=indent, label_lvl=label_lvl+lvl+"   |")
        end
      else
        print "%s  %-10s%s %s" % [label_lvl+lvl,
                                  ncol(f.name),
                                  ct.punct("="),
                                  vcol(f.i2repr(self,fvalue))]
      end
    end
    @payload.show(indent=indent, lvl=lvl+(" "*indent*self.show_indent), label_lvl=label_lvl)
  end
  
  # huh?
  def show2
    %(Prints a hierarchical view of an assembled version of the packet, so that automatic fields are calculated (checksums, etc.))
    self.__class__(str(self)).show()
  end

=begin
TODO: fix this up sometime, but I can't be bothered to right now 
    def sprintf(fmt, relax=1)
        %(sprintf(format, [relax=1]) -> str
where format is a string that can include directives. A directive begins and
ends by % and has the following format %[fmt[r],][cls[:nb].]field%.

fmt is a classic printf directive, "r" can be appended for raw substitution
(ex: IP.flags=0x18 instead of SA), nb is the number of the layer we want
(ex: for IP/IP packets, IP:2.src is the src of the upper IP layer).
Special case : "%.time%" is the creation time.
Ex : p.sprintf("%.time% %-15s,IP.src% -> %-15s,IP.dst% %IP.chksum% "
               "%03xr,IP.proto% %r,TCP.flags%")

Moreover, the format string can include conditionnal statements. A conditionnal
statement looks like : {layer:string} where layer is a layer name, and string
is the string to insert in place of the condition if it is true, i.e. if layer
is present. If layer is preceded by a "!", the result si inverted. Conditions
can be imbricated. A valid statement can be 
  p.sprintf("This is a{TCP: TCP}{UDP: UDP}{ICMP:n ICMP} packet")
  p.sprintf("{IP:%IP.dst% {ICMP:%ICMP.type%}{TCP:%TCP.dport%}}")

A side effect is that, to obtain "{" and "}" characters, you must use
"%(" and "%)".
)

        escape = { "%": "%",
                   "(": "{",
                   ")": "}" }


        # Evaluate conditions 
        while "{" in fmt
            i = fmt.rindex("{")
            j = fmt[i+1:].index("}")
            cond = fmt[i+1:i+j+1]
            k = cond.find(":")
            if k < 0
                raise Scapy_Exception("Bad condition in format string: [%s] (read sprintf doc!)"%cond)
            cond,format = cond[:k],cond[k+1:]
            res = False
            if cond[0] == "!"
                res = True
                cond = cond[1:]
            if self.haslayer(cond)
                res = not res
            if !res
                format = ""
            fmt = fmt[:i]+format+fmt[i+j+2:]

        # Evaluate directives
        s = ""
        while "%" in fmt
            i = fmt.index("%")
            s += fmt[:i]
            fmt = fmt[i+1:]
            if fmt[0] in escape
                s += escape[fmt[0]]
                fmt = fmt[1:]
                continue
            try
                i = fmt.index("%")
                sfclsfld = fmt[:i]
                fclsfld = sfclsfld.split(",")
                if len(fclsfld) == 1
                    f = "s"
                    clsfld = fclsfld[0]
                elsif len(fclsfld) == 2
                    f,clsfld = fclsfld
                else
                    raise Scapy_Exception
                if "." in clsfld
                    cls,fld = clsfld.split(".")
                else
                    cls = self.__class__.__name__
                    fld = clsfld
                num = 1
                if ":" in cls
                    cls,num = cls.split(":")
                    num = int(num)
                fmt = fmt[i+1:]
            except
                raise Scapy_Exception("Bad format string [%%%s%s]" % (fmt[:25], fmt[25:] and "..."))
            else
                if fld == "time"
                    value = time.strftime("%H:%M:%S.%%06i", time.localtime(self.time)) % int((self.time-int(self.time))*1000000)
                elsif cls == self.__class__.__name__ and hasattr(fld)
                    if num > 1
                        value = self.payload.sprintf("%%%s,%s:%s.%s%%" % (f,cls,num-1,fld), relax)
                        f = "s"
                    elsif f[-1] == "r":  # Raw field value
                        value = getattr(self,fld)
                        f = f[:-1]
                        if !f
                            f = "s"
                    else
                        value = getattr(self,fld)
                        if fld in self.fieldtype
                            value = self.fieldtype[fld].i2repr(self,value)
                else
                    value = self.payload.sprintf("%%%s%%" % sfclsfld, relax)
                    f = "s"
                s += ("%"+f) % value
            
        s += fmt
        return s
=end
  # Hah!
  
  def mysummary
    %(DEV: can be overloaded to return a string that summarizes the layer.
    Only one mysummary() is used in a whole packet summary: the one of the upper layer,
    except if a mysummary() also returns (as a couple) a list of layers whose
    mysummary() must be called if they are present.)
    return ""
  end

  def summary(internal=false)
    %(Prints a one line summary of a packet.)
    found, s, needed = @payload.summary(internal => true)
    if s
      s = " / " + s
    end

    ret = ""

    if !found or needed.member?(self.class)
      ret = self.mysummary()
      if ret.kind_of?(tuple)
        ret,n = ret
        needed += n
      end
    end

    if ret or needed
      found = 1
    end

    if !ret
      ret = self.class.name
    end

    ret = "#{ret}#{s}"

    if internal
      return found, ret, needed
    else
      return ret
    end
  end

  def lastlayer(layer=nil)
    %(Returns the highest layer of the packet)
    return @payload.lastlayer(self)
  end

  def decode_payload_as(cls)
    %(Reassembles the payload and decode it using another packet class)
    s = str(@payload)
    @payload = cls.new(s) # TODO: check me!!!
  end
      
  def libnet
    %(Not ready yet. Should give the necessary C code that interfaces with libnet to recreate the packet)
    print "libnet_build_%s(" % self.class.name.downcase
    det = self.class.new(str(self))
    fields_desc.each do |field|
      value = det.get_field_value(field.name)
      if value.nil?
        value = 0
      elsif value.kind_of?(Integer)
        value = value.to_s
      else
        value = '"%s"' % value.to_s
      end
      print "\t%s, \t\t/* %s */" % [value, field.name]
    end
    print ");"
  end

  def command
    %(Returns a string representing the command you have to type to obtain the same packet)
    f = []
    fields.each_pair do |field_name, field_value|
      if field_value.kind_of?(Packet)
        field_value = field_value.command
      else
        field_value = field_value.inspect
      end
      f << "%s=%s" % [field_name, field_value]
    end
    c = "%s(%s)" % [self.class.name, f.join(', ')]
    pc = @payload.command
    if pc
      c += "/" + pc
    end
    return c
  end                
end                       

class NoPayload < Packet

=begin
  TODO: replace with singleton include
  def __new__(cls, *args, **kargs)
    singl = cls.__dict__.get("__singl__")
    if singl.nil?
      cls.__singl__ = singl = object.__new__(cls)
      Packet.__init__(singl, *args, **kargs)
    end

    return singl
  end
=end
  # hah!

  def dissection_done(pkt)
    return
  end

  def add_payload(payload)
    raise Scapy_Exception("Can't add payload to NoPayload instance")
  end

  def remove_payload

  end

  def add_underlayer(underlayer)

  end
  def remove_underlayer(other)

  end

  def copy
    return self
  end

  def inspect
    return ""
  end

  def to_s
    return ""
  end

  def build(internal=false)
    return ""
  end

  def getfieldval(attr)
    raise AttributeError(attr)
  end

  def getfield_and_val(attr)
    raise AttributeError(attr)
  end

  def __getattr__(attr)
    if @__dict__.include?(attr)
      return self.__dict__[attr]
    elsif self.class.__dict__.include?(attr)
      return self.class.__dict__[attr]
    else
      raise AttributeError, attr
    end
  end

  def hide_defaults

  end

  def __iter__
    return iter([])
  end

  def ==(other)
    if other.kind_of?(NoPayload)
      return true
    end

    return false
  end

  def hashret
    return ""
  end

  def answers(other)
    return other.kind_of?(NoPayload) || other.kind_of?(Padding)
  end

  def haslayer(cls)
    return false
  end

  def getlayer(cls, nb=1, _track=None)
    if _track
      _track.append(nb)
    end
    return None
  end

  def show(indent=3, lvl="", label_lvl="")

  end

  def sprintf(fmt, relax)
    if relax
      return "??"
    else
      raise Scapy_Exception("Format not found [%s]"%fmt)
    end
  end

  def summary(intern=0)
    return 0,"",[]
  end

  def lastlayer(layer)
    return layer
  end

  def command
    return ""
  end
end

class Raw < Packet
  @@name = "Raw"
  @@fields_desc = [ StrField.new("load", "") ]
  
  def answers(other)
    return true
    #        s = str(other)
    #        t = self.load
    #        l = min(len(s), len(t))
    #        return  s[:l] == t[:l]
  end
end

class Padding < Raw
  @@name = "Padding"
  def build(internal=false)
    if internal
      return ""
    else
      return Raw.build(self)
    end
  end
end

class Ether < Packet
  @@name = "Ethernet"
  @@fields_desc = [ DestMACField.new("dst"),
                    SourceMACField.new("src"),
                    XShortEnumField.new("type", 0x0000, ETHER_TYPES) ]

  def hashret
    return struct.pack("H",self.type)+self.payload.hashret()
  end

  def answers(other)
    if other.kind_of?(Ether)
      if self.type == other.type
        return self.payload.answers(other.payload)
      end
    end
    return false
  end

  def mysummary
    return self.sprintf("%src% > %dst% (%type%)")
  end
end

class LLC < Packet
  @@name = "LLC"
  @@fields_desc = [ XByteField.new("dsap", 0x00),
                    XByteField.new("ssap", 0x00),
                    ByteField.new("ctrl", 0) ]
end
