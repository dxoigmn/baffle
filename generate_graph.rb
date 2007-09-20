require 'rexml/document'

include REXML

$width = 8
$height = 24

$dir = "./fingerprinting/auth_attack_flags_data/"

Dir.foreach($dir) do |filename|
  next unless filename =~ /\.csv$/
  
  doc = Document.new '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
  svg = doc.add_element "svg", "width" => "100%", "viewbox" => "0 0 100 100", "version" => "1.1", "xmlns" => "http://www.w3.org/2000/svg"

  File.open $dir + filename do |csv|
    max_count = 0
    
    x = 0
        
    csv.each_line do |line|
      if line =~ /^(........),(.)$/
        count = $2.to_i
        
        max_count = count if count > max_count
      end
    end
    
    csv.seek(0)

    total_width = 0

    csv.each_line do |line|
      if line =~ /^(........),(.)$/
        respond_count = $2.to_i
        
        alpha = (respond_count / max_count.to_f) ** 4 + 0.05

        total_width += $width * alpha + 1        
      end
    end

    csv.seek(0)

    csv.each_line do |line|
      if line =~ /^(........),(.)$/
        flags = $1
        respond_count = $2.to_i

        flags_value = flags.to_i(2)
      
        alpha = (respond_count / max_count.to_f) ** 4 + 0.05
        
        width = ($width * alpha + 1) / total_width * 600.0
      
        flags.split(//).each_with_index do |c, i|
          y = 1 + i * ($height + 1)
          color = (c == "0") ? "black" : "red"

          svg.add_element "rect", "x" => x, "y" => y, "width" => width, "height" => $height, "style" => "fill:#{color};fill-opacity:#{alpha}"
        end
        
        x += width
      end
    end
  end

  File.open $dir + filename + ".svg", "w" do |graph|
    graph.write doc.to_s(0)
  end
end