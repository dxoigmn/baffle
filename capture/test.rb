require 'capture'

Capture.open :device => 'en0', :snapshot_length => 8, :filter => 'tcp port 22' do |capture|
  capture.each(10) do |packet|
    p packet
  end
end
