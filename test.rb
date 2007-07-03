require "baflle"

add_rule :rule1,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11),
         :pass => "Linksys",
         :fail => :rule2

add_rule :rule2,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11),
         :pass => "Aruba",
         :fail => "Unknown"

puts eval("ath0", "madwifing", :rule1)