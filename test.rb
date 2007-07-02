require "baflle"

add_rule :rule1,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11), # or string bpf filter!
         :pass => "Linksys",
         :fail => :rule2,  # timeout, or not match packet
         :timeout => 5

add_rule :rule2,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11), # of string bpf filter
         :pass => "Aruba",
         :fail => "Unknown",
         :timeout => 5

puts eval(:rule1)


# expect <= if PacketSet, assume ruby filtering, if String assume tcpdump filter