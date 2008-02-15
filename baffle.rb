#!/usr/bin/env ruby
require 'rubygems'
require 'ramaze'
#require File.join(File.dirname(__FILE__), 'tool', 'tool')

class MainController < Ramaze::Controller
  def index
    html =<<END
<html>
  <head>
    <title>baffle</title>
  </head>
  <body>
    <h1>baffle</h1>
    
    <form action="fingerprint" method="get">
      <label for="target">target:</target>
      <input type="text" name="target" /><br />
      <label for="essid">essid:</target>
      <input type="text" name="essid" /><br />
      <input type="submit" value="fingerprint" />
    </form>
  </body>
</html>
END

    html
  end
  
  def fingerprint
    target  = request[:target]
    essid   = request[:essid]

    
    Process.detach Kernel.fork{system("cd tool && ./tool.rb -e #{essid} #{target} -f ../public/#{target.gsub(/:/, '_')}_")}
    #Baffle.run(["-e", essid, target, "-f", target.gsub(/:/, '_')])


    redirect "/image?i=#{target.gsub(/:/, '_')}_auth_flags.svg"
  end
  
  def image
    image = request[:i]

    src =<<END
<html>
  <head>
    <style type="text/css">
      body {
        background-color: #666666;
        color: #ffffff;
      }

      .loading {
        width: 100px;
        height: 100px;
        background: url(fingerprint.gif) no-repeat center center;
      }
    </style>
    <script src="jquery.js"></script>
    <script type="text/javascript">
      function loadImage() {
        $.get('#{image}', function(data) {
          $('#loader').removeClass('loading');
          clearInterval(loader);
          //$("#loader").append('<iframe src="#{image}" width="100" height="100" border="0">');
          $("#loader").append('<embed src="#{image}" width="500px" height="500px" border="0"');
        });
      }

      var loader = setInterval("loadImage()", 3000);
    </script>
  </head>
  <body>
    <center>
    <h1>#{image.gsub('_', ':')}</h1>
    <div class="loading" id="loader"></div>
    </center>
  </body>
</html>
END

    src
  end
end

Ramaze.start(:adapter => :mongrel, :port => 4567)
