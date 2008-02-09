probe "flags" do
  inject Baffle::Dot11::ProbeRequest.new(:flags => 0..9)
  
  capture Baffle::Dot11::ProbeResponse.new { 1 }
  capture :timeout { 0 }
  
  train "Linksys", [1, 0, 0, 0, 0, 0, 0, 0, 0, 1]
end
