require 'rubygems'
require 'sinatra'
require File.join(File.dirname(__FILE__), 'tool/tool')

get '/' do 
  "hey hey"
end

get '/fingerprint' do
  target = params[:target]
  essid = params[:essid]
  
  Thread.new do
    puts "my new thread!!!"
    Baffle.run(["-e", essid, target, "-f", target.gsub(/:/, '_')])
    puts "I iz dun"
  end
  
  redirect "/image?i=#{target.gsub(/:/, '_')}_auth_flags.svg"
end

get "/image" do
  image = params[:i]
  
  src =<<END
<html>
  <body>
    <meta http-equiv="refresh" content="1"> 
    moo!
    <img src="/#{image}"/>
  </body>
</html>
END
end


