require "baflle"

add_rule :rule1,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11), # or string bpf filter!
         :pass => Proc.new { puts "Linksys" },
         :fail => :rule2,  # timeout, or not match packet
         :timeout => 5000

add_rule :rule2,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11), # of string bpf filter
         :pass => Proc.new { puts "Aruba" },
         :fail => Proc.new { puts "Unknown" },
         :timeout => 5000

puts eval_rules


# expect <= if PacketSet, assume ruby filtering, if String assume tcpdump filter