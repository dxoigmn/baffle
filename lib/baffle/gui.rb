#!/usr/bin/env ruby

require 'gtk2'
require 'libglade2'
require 'tempfile'
require 'rubygems'
require 'baffle'

module Baffle
  class Gui
    @@glade_path = File.expand_path(File.join(File.dirname(__FILE__), 'baffle.glade'))

    def initialize(options)
      @glade = GladeXML.new(@@glade_path) { |handler| method(handler) }
      @options = options

      @mac_addresses = @glade.get_widget('mac_addresses')
      @mac_addresses.model = Gtk::ListStore.new(String)
      @mac_addresses.text_column = 0
      
      on_refresh_clicked(@mac_addresses)
    end
  
    def on_refresh_clicked(widget)
      iwlist = `iwlist #{@options.capture} scan`
    
      essid = nil
      bssid = nil

      @mac_addresses.model.clear

      iwlist.each_line do |line|
        bssid = $1 if line =~ /Cell \d+ - Address: (([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})/      
        essid = $1 if line =~ /ESSID:"([^"]+)"/
   
        @mac_addresses.append_text("#{bssid} #{essid}") if essid 

        essid = nil
      end
    end

    def on_scan_selected_clicked(widget)
      args = parse(@mac_addresses.active_text)
      scan(*args) if args
    end

    def on_scan_all_clicked(widget)
      @mac_addresses.model.each do |model, path, iter|
        args = parse(iter.get_value(0))
        scan(*args) if args
      end
    end

    private
    
    def parse(text)
      return $1, $3 if text =~ /^(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}) (.*)$/ 
    end

    def scan(bssid, essid)
      @options.essid = essid
      @options.bssid = bssid

      Baffle::Probes.each do |probe|
        puts "Running probe #{probe.name}"
        vector = probe.run(@options)

        unless vector
          warn "Probe was skipped."
          next
        end

        temp = Tempfile.new('baffle.svg')

        File.open(temp.path, 'w+') do |f|
          f << Baffle.fingerprint_diagram(vector).to_s 
        end

        hypothesis = probe.hypothesize(vector)

        # Add to Gtk
      end     
    end
  end
end
