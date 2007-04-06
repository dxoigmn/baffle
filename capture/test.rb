require 'capture'

capture = Capture.open_live('en0', 680)

capture.each_packet do |moo|
  puts moo
end