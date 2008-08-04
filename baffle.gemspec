Gem::Specification.new do |s|
  s.name          = 'baffle'
  s.version       = '0.0.7'
  s.date          = '2008-08-02'
  s.summary       = 'A Behavioral Active Fingerprinting tool for 802.11 APs, operating entirely within the Link Layer.'
  s.homepage      = 'http://github.com/dxoigmn/baffle'
  s.description   = 'A Behavioral Active Fingerprinting tool for 802.11 APs, operating entirely within the Link Layer.'
  s.files         = [ 'README.markdown',
                      'LICENSE',
                      'bin/baffle',
                      'lib/baffle.rb',
                      'lib/baffle/fingerprint_diagram.rb',
                      'lib/baffle/options.rb',
                      'lib/baffle/probe.rb',
                      'lib/baffle/util.rb',
                      'lib/baffle/gui.rb',
                      'lib/baffle/gui.glade',
                      'lib/baffle/probes/authreq_flags.rb',
                      'lib/baffle/probes/probereq_flags.rb',
                      'data/probes.yml' ]
  s.require_paths = [ 'lib' ]
  s.executables   = [ 'baffle' ]
  
  s.add_dependency('dxoigmn-rb-lorcon', ['>= 0.1.0'])
  s.add_dependency('dxoigmn-rb-pcap', ['>= 0.1.0'])
  s.add_dependency('dxoigmn-dot11', ['>= 0.1.0'])
  s.add_dependency('facets', ['>= 2.4.1'])
end
