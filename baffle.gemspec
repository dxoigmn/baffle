Gem::Specification.new do |s|
  s.authors       = ['Cory T. Cornelius']
  s.email         = ['cory.t.cornelius@dartmouth.edu']
  s.name          = 'baffle'
  s.version       = '0.2.1'
  s.date          = '2008-08-02'
  s.summary       = 'A Behavioral Active Fingerprinting tool for 802.11 APs, operating entirely within the Link Layer.'
  s.homepage      = 'http://baffle.cs.dartmouth.edu/'
  s.description   = 'See README.markdown for more information.'
  s.files         = [ 'README.markdown',
                      'LICENSE',
                      'bin/baffle',
                      'lib/baffle.rb',
                      'lib/baffle/fingerprint_diagram.rb',
                      'lib/baffle/gtk_queue.rb',
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

  s.add_dependency('rb-lorcon', ['>= 0.1.0'])
  s.add_dependency('rb-pcap', ['>= 0.1.0'])
  s.add_dependency('dot11', ['>= 0.1.0'])
  s.add_dependency('facets', ['>= 2.4.1'])
end
