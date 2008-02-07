#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "options")
require 'rubygems'
require 'SVM'

options = Baffle::Options.parse(ARGV)
p options