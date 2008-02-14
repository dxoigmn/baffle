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

    redirect "/image?i=#{target.gsub(/:/, '_')}_auth_flags.svg"
  end
  
  def image
    image = request[:i]

    src =<<END
<html>
  <body>
    <meta http-equiv="refresh" content="1"> 
    moo!
    <img src="/#{image}"/>
  </body>
</html>
END

    src
  end
end

Ramaze.start(:adapter => :mongrel, :port => 4567)