require "packet"

class Radiotap < Packet
  name "Radiotap Header"
  
  unsigned  :revision, 8, "Revision"
  unsigned  :pad, 8, "Pad"
  unsigned  :stuff_length, 16, "Length of Stuff", :endian => :little
  char      :stuff, proc { |instance| (instance.stuff_length - 4) * 8 }, "Stuff"
  nest      :frame, nil, "802.11 Frame", :nested_class => Dot11
end