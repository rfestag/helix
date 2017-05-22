#!/usr/bin/env ruby
require 'helix'
key = File.join(File.dirname(__FILE__), 'test.key')
cert = File.join(File.dirname(__FILE__), 'test.crt')
s = Helix::Server.new '0.0.0.0', 1337, key: key, cert: cert
$DEBUG = false
$VERBOSE = false
s.run
