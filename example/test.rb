require 'helix'
s = Helix::Server.new '0.0.0.0', 1337, key: './test.key', cert: './test.crt'
$DEBUG = false
$VERBOSE = false
s.run
