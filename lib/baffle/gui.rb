#!/usr/bin/env ruby

require 'gtk2'
require 'libglade2'
require 'tempfile'
require 'rubygems'

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'baffle.rb'))
require File.expand_path(File.join(File.dirname(__FILE__), 'gtk_queue.rb'))

module Baffle
  class Gui
    @@glade_path = File.expand_path(File.join(File.dirname(__FILE__), 'gui.glade'))
    
    def initialize(options)
      @glade = GladeXML.new(@@glade_path) { |handler| method(handler) }
      @options = options
      
      @window = @glade.get_widget('window')
      @window.signal_connect("destroy") { Gtk.main_quit }
      
      @mac_addresses = @glade.get_widget('mac_addresses')
      @mac_addresses.model = Gtk::ListStore.new(String)
      @mac_addresses.text_column = 0
      
      @results = @glade.get_widget('results')
      
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
      
      @mac_addresses.active = 0
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
    
    def on_remove_clicked(widget)
      @mac_addresses.remove_text(@mac_addresses.active)
      @mac_addresses.active = 0
    end
    
    private
    
    def parse(text)
      return $1, $3 if text =~ /^(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}) (.*)$/ 
    end
    
    def scan(bssid, essid)
      @options.essid = essid
      @options.bssid = bssid
      
      progress = Gtk::ProgressBar.new
      progress.pulse_step = 0.05
      
      page = Gtk::ScrolledWindow.new
      page.add_with_viewport(Gtk::VBox.new.add(progress))
      page.set_policy(Gtk::POLICY_NEVER, Gtk::POLICY_AUTOMATIC)
      
      @results.append_page(page, Gtk::Label.new("#{bssid} #{essid}"))
      @window.show_all
      
      updated_page = Gtk::VBox.new
      
      Thread.new do
        progress_count = 0
        progress_total = Baffle::Probes.total_injection_values
        
        Baffle::Probes.each do |probe|
          Gtk.queue { progress.text = "Running #{probe.name} probe..." }
          
          vector = probe.run(@options) do
            progress_count += 1
            
            Gtk.queue { progress.fraction = progress_count.to_f / progress_total.to_f }
          end
          
          unless vector
            warn "Probe was skipped."
            next
          end
          
          temp = Tempfile.new('baffle.svg')
          temp_path = temp.path
          temp.close!
          
          File.open(temp_path, 'w') do |f|
            f << Baffle.fingerprint_diagram(vector).to_s
          end

          hypothesis = probe.hypothesize(vector)
          
          Gtk.queue do
            updated_page.add(Gtk::Label.new(hypothesis)).add(Gtk::Image.new(temp_path))
          end
        end
        
        finished = true
        
        Gtk.queue do
          page.each do |child|
            page.remove(child)
          end
          page.add_with_viewport(updated_page)
          @window.show_all
        end
      end
    end
    
    def self.run(options)
      Gui.new(options)
      Gtk.main_with_queue
    end
  end
end
