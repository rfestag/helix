require "nio"
require "socket"
require 'openssl'
require 'http/2'

module Helix
  class Server
    ALPN_PROTOCOL        = 'h2'
    ALPN_SELECT_CALLBACK = ->(ps){ ps.find { |p| ALPN_PROTOCOL == p }}
    ECDH_CURVES          = 'P-256'
    TMP_ECDH_CALLBACK    = ->(*_){ OpenSSL::PKey::EC.new 'prime256v1' }
  
    ECDH_OPENSSL_MIN_VERSION = '2.0'
    ALPN_OPENSSL_MIN_VERSION = 0x10002001
  
    def initialize(host, port, **opts, &block)
      @selector = NIO::Selector.new
      @on_request = block
  
      puts "Listening on #{host}:#{port}"
      @server = TCPServer.new(host, port)
      @context = create_ssl_context(opts)
  
      monitor = @selector.register(@server, :r)
      monitor.value = proc { |m| accept }
    end
  
    def run
      loop do
        begin
          @selector.select { |monitor| monitor.value.call(monitor) }
        rescue => e
          puts "#{e.class}: #{e.message} (select)"
          puts e.backtrace.join("\n")
        end
      end
    end
  
    def accept
      sock = @server.accept_nonblock exception: false
      return if sock == :wait_readable
  
      ssl_sock = OpenSSL::SSL::SSLSocket.new(sock, @context)
      ssl_sock.sync = true
      accept_ssl(ssl_sock)
    end
    def accept_ssl ssl_sock, monitor=nil
      begin
        client = ssl_sock.accept_nonblock exception: false

        if client == :wait_readable 
          return await ssl_sock, monitor, :r
        elsif client == :wait_writeable
          return await ssl_sock, monitor, :w
        end
  
        _, port, host = client.peeraddr
        puts "*** #{host}:#{port} connected"

        Helix::Connection.new client, @selector, monitor, &@on_request
      rescue => e
        puts "#{e.class}: #{e.message} (accept)"
        puts e.backtrace.join("\n")
        if client
          @selector.deregister(client)
          client.close
        end
        puts "Closed (accept)"
      end
    end
    def await socket, monitor, interest
      if monitor
        monitor.interests = :r
      else
        monitor = @selector.register(socket, :r)
      end
      monitor.value = proc { accept_ssl(socket, monitor) }
      return monitor
    end
    def create_ssl_context **opts
      ctx                  = OpenSSL::SSL::SSLContext.new
      ctx.ca_file          = opts[:ca_file] if opts[:ca_file]
      ctx.ca_path          = opts[:ca_path] if opts[:ca_path]
      ctx.cert             = context_cert opts[:cert]
      ctx.ciphers          = opts[:ciphers] || OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
      ctx.extra_chain_cert = context_extra_chain_cert opts[:extra_chain_cert]
      ctx.key              = context_key opts[:key]
      ctx.options          = opts[:options] || OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options]
      ctx.ssl_version      = :TLSv1_2
      context_ecdh ctx
      context_set_protocols ctx
      ctx
    end
  
    if OpenSSL::VERSION >= ECDH_OPENSSL_MIN_VERSION
      def context_ecdh ctx
        ctx.ecdh_curves = ECDH_CURVES
      end
    else
      def context_ecdh ctx
        ctx.tmp_ecdh_callback = TMP_ECDH_CALLBACK
      end
    end
  
    def context_cert cert
      case cert
      when String
        cert = File.read cert if File.exist? cert
        OpenSSL::X509::Certificate.new cert
      when OpenSSL::X509::Certificate
        cert
      end
    end
  
    def context_key key
      case key
      when String
        key = File.read key if File.exist? key
        OpenSSL::PKey::RSA.new key
      when OpenSSL::PKey::RSA
        key
      end
    end
    def context_extra_chain_cert chain
      case chain
      when String
        chain = File.read chain if File.exist? chain
        [OpenSSL::X509::Certificate.new(chain)]
      when OpenSSL::X509::Certificate
        [chain]
      when Array
        chain
      end
    end
  
    if OpenSSL::OPENSSL_VERSION_NUMBER >= ALPN_OPENSSL_MIN_VERSION
      def context_set_protocols ctx
        ctx.alpn_protocols = [ALPN_PROTOCOL]
        ctx.alpn_select_cb = ALPN_SELECT_CALLBACK
      end
    else
      def context_set_protocols ctx
        ctx.npn_protocols = [ALPN_PROTOCOL]
        ctx.npn_select_cb = ALPN_SELECT_CALLBACK
      end
    end
  end
end
