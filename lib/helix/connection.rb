require "nio"
require "socket"
require 'openssl'
require 'http/2'

module Helix
  class Connection
    def initialize socket, selector, monitor
      resp = "TEST DATA"
      @socket = socket
      @monitor = monitor
      @selector = selector
      @conn = HTTP2::Server.new
      @conn.on(:frame) {|bytes| write(bytes)}
      @conn.on(:stream) do |stream|
        req = {}
        buffer = NIO::ByteBuffer.new(16384)
        stream.on(:headers) do |h|
          req = Hash[*h.flatten]
        end
        stream.on(:data) do |d|
          buffer << d
        end
        stream.on(:half_close) do
          buffer.flip
          response = nil
          stream.headers({
            ':status' => '200',
            'content-length' => resp.length.to_s
          }, end_stream: false)
          stream.data(resp)
        end
      end
  
      read
    end
    def write bytes
      result = @socket.write_nonblock(bytes, exception: false)
      if result == :wait_writeable
        if @monitor
          @monitor.interests = :w
        else
          @monitor = @selector.register(@socket, :w) unless monitor
        end
        @monitor.value = proc {read}
      end
    end
    def read
      until (data = @socket.read_nonblock(4096, exception: false)) == :wait_readable
        raise EOFError.new if data.nil?
        @conn << data
      end
      if @monitor
        @monitor.interests = :r
      else
        @monitor = @selector.register(@socket, :r) unless monitor
      end
      @monitor.value = proc {read}
    rescue EOFError, Errno::EPIPE, Errno::ECONNRESET => e
      begin
        _, port, host = @socket.peeraddr
        puts "*** #{host}:#{port} disconnected"
      rescue
        puts "Something disconnected, not sure what"
      end
      @selector.deregister(@socket)
      @socket.close
      false
    rescue => e
      puts "#{e.class}: #{e.message} (read)"
      @selector.deregister(@socket)
      begin
        _, port, host = @socket.peeraddr
        puts "*** #{host}:#{port} disconnected (read)"
      rescue
        puts "Something disconnected, not sure what (read)"
      end
      @socket.close
      false
    end
  end
end
