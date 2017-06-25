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
  
    def initialize(host, port, **opts)
      @selector = NIO::Selector.new
  
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
      return sock if sock == :wait_readable
  
      ssl_sock = OpenSSL::SSL::SSLSocket.new(sock, @context)
      ssl_sock.sync = true
      client,monitor = accept_ssl(ssl_sock)
  
      if monitor
        @selector.interests = :r if client == :wait_readable
        @selector.interests = :w if client == :wait_writeable
      else
        if client == :wait_readable 
          monitor = @selector.register(ssl_sock, :r)
          monitor.value = proc { accept_ssl(ssl_sock, monitor) }
        elsif client == :wait_writeable
          monitor = @selector.register(ssl_sock, :w)
          monitor.value = proc { accept_ssl(ssl_sock, monitor) }
        end
      end
    end
    def accept_ssl ssl_sock, monitor=nil
      begin
        #client = ssl_sock.accept
        client = ssl_sock.accept_nonblock exception: false
  
        return [client,monitor] if  client == :wait_readable || client == :wait_writeable
  
        #The client will disconnect automatically if ALPN
        #re-negotiates H2
        _, port, host = client.peeraddr
        puts "*** #{host}:#{port} connected"

        connection = Helix::Connection.new client, @selector, monitor
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

Helix::Server.new("localhost", 1234, key: 'test.key', cert: 'test.crt').run if $PROGRAM_NAME == __FILE__
