#!/usr/bin/ruby
require "baflle-recv"

trap "INT" do
  puts "Flags\t\t\tCount"
  puts "-" * 30
  @flags.each_with_index do |count, index|
    puts "0x%02x\t%08b\t%d" % [index, index, count]
  end
  
  abort
end
                
eval "ath0"
