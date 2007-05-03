#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

  # Getting the OS. This will be useful for sending packets on the
  # loopback device.
  os = RUBY_PLATFORM
  $IS_OPENBSD = os.include?('openbsd')
  $IS_BSD = os.include?('bsd')
  $IS_LINUX = os.include?('linux')
  $IS_WINDOWS = os.include?('mswin')

  # Knowing whether we have libdnet or not will be useful for sending packets.
  $HAVE_LIBDNET = false

  # Importing non-standard modules, they are all mandatory.
  begin
    require 'pcaprub'
  rescue Exception
    puts 'FATAL: Pcaprub module not found.'
    exit
  end

  # Importing Libdnet module (not mandatory).
  begin
    require 'dnet'
    $HAVE_LIBDNET = true
  rescue Exception
    puts 'WARNING: Dnet module not found.'
  end

  # This is part of the core distribution.
  require 'ipaddr'

  # Requiring other Scruby files
  require 'conf'
  require 'const'
  require 'layer'
  require 'packet'
  require 'field'
  require 'dissectors'
  require 'func'
  require 'help'
  require 'dot11'

  # Creating string arrays for dissectors and fields
  DISSECTOR_LIST_S = DISSECTOR_LIST.map{|e| e.to_s.split('::')[1]}
  FIELD_LIST_S = FIELD_LIST.map{|e| e.to_s}

  # This is used to allow creating objects without using "new",
  # e.g. p=IP() instead of p=IP.new()
  def Scruby.method_missing(method, *args)

    # Looking for the field corresponding to 'method'
    index = DISSECTOR_LIST_S.index(method.to_s)

    # If no dissector was found
    raise NameError, "undefined local variable or method `#{method}' for #{self}" if index.nil?

    # If a string was passed, let's try to dissect it as a Packet
    if args[0].is_a?(String)
      return Packet.new(args[0], method.to_s)

      # Otherwise, instantiating the class with arguments if supplied
    else
      DISSECTOR_LIST[index].__send__('new', *args)
    end
  end

  # Same as above, for fields
  def Scruby.field(method, *args)

    # Looking for the field corresponding to 'method'
    index = FIELD_LIST_S.index('Scruby::' + method.to_s)

    # If no field was found
    raise NameError, "undefined local variable or method `#{method}' for #{self}" if index.nil?
            
    # Instantiating the class with arguments if supplied
    FIELD_LIST[index].__send__(:new, *args)
  end

  # Loading global configuration
  $conf = Conf.new()

  # If we were not called from a module, let's spawn a shell.
  if __FILE__ == $0

    # This is part of the core distribution.
    begin
      require 'readline'
    rescue Exception
      puts 'FATAL: module Readline not found.'
      exit
    end

    # Welcome :)
    SCRUBY_VERSION = '0.1'
    puts "Welcome to Scruby (#{SCRUBY_VERSION}) Copyright 2007 Sylvain SARMEJEANNE"
    puts 'If you\'re lost, just shout for "help".'

    # Setting the terminal
    prompt = 'scruby> '

    Readline.completion_proc = proc do |word| 
      (FUNCTION_LIST + DISSECTOR_LIST_S).grep(/\A#{Regexp.quote word}/)
    end

    # Main loop
    begin
      line = Readline.readline(prompt, RECORD_HISTORY)
      begin
        puts(eval(line)) if line != nil
      rescue Exception => e
        puts e.message
      end
    end until line == nil

    puts

  end
end
