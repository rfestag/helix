#!/usr/bin/env ruby
require 'helix'
key = File.join(File.dirname(__FILE__), 'test.key')
cert = File.join(File.dirname(__FILE__), 'test.crt')
s = Helix::Server.new("localhost", 1234, key: key, cert: cert) do |headers, data, stream|
  [{':status' => '200'}]
end
s.run
