require 'capture'

Capture.open :device => 'en0', :limit => 10 do |capture|
  capture.each do |packet|
    p packet
  end
end
