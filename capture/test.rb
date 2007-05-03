require 'capture'

Capture.open :device => 'eth1', :limit => 10 do |capture|
  capture.each do |packet|
    p packet
  end
end
