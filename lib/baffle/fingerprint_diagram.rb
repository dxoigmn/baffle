require 'rexml/document'

include REXML

module Baffle
  WIDTH = 24
  HEIGHT = 24
  
  def self.fingerprint_diagram(vector)
    doc = Document.new '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
    svg = doc.add_element "svg", "width" => "100%", "viewbox" => "0 0 100 100", "version" => "1.1", "xmlns" => "http://www.w3.org/2000/svg"
    
    max_count = 0
    
    x = 0
    
    max_count = vector.max
    
    total_width = 32 * WIDTH *  1.05
    
    vector.each_with_index do |respond_count, flags_value|
      alpha = (respond_count / max_count.to_f) ** 3 + 0.1
      width = (WIDTH * alpha + 1) / total_width * 600.0
      
      alpha = 1 if alpha.nan?
      width = WIDTH if width.nan?
      
      alpha = (respond_count > 1 ? 1 : 0.05)
      width = 3
      
      ("%08d" %flags_value.to_s(2)).split(//).each_with_index do |c, i|
        y = 1 + i * (HEIGHT + 1)
        color = (c == "0") ? "black" : "red"
        
        svg.add_element "rect", "x" => x - (width / 2), "y" => y, "width" => width, "height" => HEIGHT, "style" => "fill:#{color};fill-opacity:#{alpha}"
      end
      
      x += total_width / 256
    end
    
    svg
  end
end
