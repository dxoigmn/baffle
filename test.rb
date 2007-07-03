require "baflle"

add_rule :rule1,
         :send => Dot11.new(:type => 3, :subtype => 15, :proto => 3),
         :expect => Dot11.new(),
         :pass => "Linksys",
         :fail => :rule2

add_rule :rule2,
         :send => PacketSet.new(:class => Dot11),
         :expect => PacketSet.new(:class => Dot11),
         :pass => "Aruba",
         :fail => "Unknown"

puts eval("ath0", "madwifing", :rule1)