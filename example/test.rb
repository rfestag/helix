#!/usr/bin/env ruby
require 'helix'
key = File.join(File.dirname(__FILE__), 'test.key')
cert = File.join(File.dirname(__FILE__), 'test.crt')
s = Helix::Server.new("localhost", 1234, key: key, cert: cert).run if $PROGRAM_NAME == __FILE__
s.run
