require 'monitor'

module Gtk
  GTK_PENDING_BLOCKS = []
  GTK_PENDING_BLOCKS_LOCK = Monitor.new

  def Gtk.queue(&block)
    if Thread.current == Thread.main
      block.call
    else
      GTK_PENDING_BLOCKS_LOCK.synchronize do
        GTK_PENDING_BLOCKS << block
      end
    end
  end

  def Gtk.main_with_queue(timeout=100)
    Gtk.timeout_add(timeout) do
      GTK_PENDING_BLOCKS_LOCK.synchronize do
        GTK_PENDING_BLOCKS.each { |block| block.call }
        GTK_PENDING_BLOCKS.clear
      end
      
      true
    end
    
    Gtk.main
  end
end
