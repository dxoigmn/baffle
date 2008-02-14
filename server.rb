#!/usr/bin/env ruby
require 'rubygems'
require 'ramaze'
#require File.join(File.dirname(__FILE__), 'tool', 'tool')

class MainController < Ramaze::Controller
  def fingerprint
    target  = request[:target]
    essid   = request[:essid]

    Thread.new do
      Baffle.run(["-e", essid, target, "-f", target.gsub(/:/, '_')])
    end

    redirect "/image?i=#{target.gsub(/:/, '_')}_auth_flags.jpg"
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
        var img = new Image();

        $(img).load(function () {
          $('#loader').removeClass('loading');
          clearInterval(int);
          $("#loader").append('<iframe src="#{image}" width="100" height="100" border="0"'>)
        }).attr('src', '#{image}');
      }

      var int = setInterval("loadImage()", 1000);
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