#!/usr/bin/env ruby
require 'rubygems'
require 'ramaze'
require File.join(File.dirname(__FILE__), 'tool', 'tool')

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

        // wrap our new image in jQuery, then:
        $(img)
        // once the image has loaded, execute this code
        .load(function () {
          // set the image hidden by default    
          $(this).hide();

          // with the holding div #loader, apply:
          $('#loader')
            // remove the loading class (so no background spinner), 
            .removeClass('loading')
            // then insert our image
            .append(this);

          // fade our image in to create a nice effect
          $(this).fadeIn();
          clearInterval(int);
        })

        // if there was an error loading the image, react accordingly
        .error(function () {
          // notify the user that the image could not be loaded
        })

        // *finally*, set the src attribute of the new image to our image
        .attr('src', '#{image}');
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