#!/usr/bin/env ruby

require 'capture'

a = Capture::Filter.new("ether[4] == 3")