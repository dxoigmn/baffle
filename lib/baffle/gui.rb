#!/usr/bin/env ruby

require 'gtk2'
require 'libglade2'
require 'tempfile'
require 'thread'

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'baffle.rb'))
require File.expand_path(File.join(File.dirname(__FILE__), 'gtk_queue.rb'))

module Baffle
  class Gui
    @@glade_path = File.expand_path(File.join(File.dirname(__FILE__), 'gui.glade'))
    
    def initialize(options)
      @glade = GladeXML.new(@@glade_path) { |handler| method(handler) }
      @options = options
      @scan_lock = Mutex.new
      
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
    
    def on_load_clicked(widget)
      dialog = Gtk::FileChooserDialog.new("Choose a Kismet CSV file", @window, Gtk::FileChooser::ACTION_OPEN, nil, [Gtk::Stock::OPEN, Gtk::Dialog::RESPONSE_ACCEPT], [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL])
      
      if dialog.run == Gtk::Dialog::RESPONSE_ACCEPT
        @mac_addresses.model.clear
        
        File.open(dialog.filename).each_line do |line|
          num, type, essid, bssid, rest = line.split(';')
          
          @mac_addresses.append_text("#{bssid} #{essid}") if type == 'infrastructure' && bssid =~ /^(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$/ 
        end
        
        @mac_addresses.active = 0
      end
      
      dialog.destroy
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
      
      page_label = Gtk::Label.new("#{bssid} #{essid}")
      
      @results.append_page(page, page_label)
      @window.show_all
      
      cur_page = @results.n_pages - 1
      updated_page = Gtk::VBox.new
      
      Thread.new do
        Gtk.queue { progress.text = 'Waiting to acquire scan lock...' }
        
        @scan_lock.lock
        
        Gtk.queue { @results.page = cur_page }
        
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
        
        Gtk.queue do
          page.each do |child|
            page.remove(child)
          end
          page.add_with_viewport(updated_page)
          page_label.set_markup("<b>#{page_label.text}</b>")
          @window.show_all
        end
        
        @scan_lock.unlock
      end
    end
    
    def self.run(options)
      Gui.new(options)
      Gtk.main_with_queue
    end
  end
end
