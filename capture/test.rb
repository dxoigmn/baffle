#!/usr/bin/env ruby

require 'capture'

capture = Capture.open(:device => (ARGV[0] || 'ath0'), :dump => 'dump') do |capture|
  (1..10).each do
    print '.'
    STDOUT.flush 
    capture.dispatch
  end
  
  puts
end