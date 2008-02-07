#!/usr/bin/env ruby

require 'capture'

Capture.open :device => (ARGV[0] || 'ath0'), :limit => 10 do |capture|
  capture.each do |packet|
    p packet
  end
end
