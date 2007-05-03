require "capture/capture"
require "packetset"
require "thread"

@rules = {
          :rule1 =>  {
                      :send => PacketSet.new(:type => 1..3),
                      :filter => Proc.new { |packet| true },
                      :expect => PacketSet.new(:type => 4..6),
                      :pass => Proc.new { puts "Linksys" },
                      :fail => :rule2
                     },
          :rule2 =>  {
                      :send => PacketSet.new(:type => 7..9),
                      :filter => Proc.new { |packet| true },
                      :expect => PacketSet.new(:type => 10..12),
                      :pass => Proc.new { puts "Aruba" },
                      :fail => Proc.new { puts "Unknown" }
                    }
        }

def eval_rule(rule)
  sent = false
  packet = nil

  # Setup capture thread
  capture = Thread.new do
    Capture.open :device => "eth1" do |capture|
      capture.each do |pkt|

        if sent and rule[:filter].call(pkt)
          packet = pkt 
          break
        end
      end
    end
  end

  # Send packet
  sent = true
  # TODO: Sent packet via lorcon

  # Wait for capture thread to return
  capture.join

  # Process packet
  if rule[:expect].include? packet
    next_rule = rule[:pass]
  else
    next_rule = rule[:fail]
  end

  # Evaluate next rule/proc
  case next_rule.class.name
    when "Symbol"
      eval_rule @rules[next_rule]
    when "Proc"
      next_rule.call
  end
end

@rules.each do |name, rule|
  eval_rule rule
end
