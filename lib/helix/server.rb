require 'async'
require 'async/tcp_socket'
require 'async/ssl_socket'
require 'http/2'

module Helix
  class Server 
    ALPN_PROTOCOL        = 'h2'
    ALPN_SELECT_CALLBACK = ->(ps){ ps.find { |p| ALPN_PROTOCOL == p }}
    ECDH_CURVES          = 'P-256'
    TMP_ECDH_CALLBACK    = ->(*_){ OpenSSL::PKey::EC.new 'prime256v1' }

    ECDH_OPENSSL_MIN_VERSION = '2.0'
    ALPN_OPENSSL_MIN_VERSION = 0x10002001

    def initialize host, port, sni: {}, **options
      @reactor = Async::Reactor.new
      @sni = sni
      @sni_callback = @sni[:callback] || method(:sni_callback)
      @tcpserver = TCPServer.new(host, port)
      @sslserver = OpenSSL::SSL::SSLServer.new(@tcpserver, create_ssl_context(options))
      options.merge! host: host, port: port, sni: sni
      #TODO: Start server?
    end
    # default SNI callback - builds SSLContext from cert/key by domain name in +@sni+
    # or returns existing one if name is not found
    #
    def sni_callback args
      socket, name = args
      @contexts ||= {}
      if @contexts[name]
        @contexts[name]
      elsif sni_opts = @sni[name] and Hash === sni_opts
        @contexts[name] = create_ssl_context sni_opts
      else
        socket.context
      end
    end
    def run
      resp = "TEST DATA"
      @reactor.async(@sslserver) do |server, task|
        puts "Starting server"
        while true
          begin
            task.with(server.accept) do |sock|
              puts "Accepted connection"
              conn = HTTP2::Server.new
              conn.on(:frame) {|bytes| sock.write(bytes)}
              conn.on(:stream) do |stream|
                req, buffer = {}, ''
                stream.on(:active) {puts "#{conn} #{stream.id}: client opened new stream"}
                stream.on(:close) {puts "#{conn} #{stream.id}: stream closed"}
                stream.on(:headers) do |h|
                  req = Hash[*h.flatten]
                  puts "#{conn} #{stream.id}: #{req}"
                end
                stream.on(:data) do |d|
                  buffer << d
                end
                stream.on(:half_close) do
                  response = nil
                  puts "#{conn} #{stream.id}: Responding"
                  stream.headers({
                    ':status' => '200',
                    'content-length' => resp.length.to_s
                  }, end_stream: false)
                  stream.data(resp)
                end
              end
              begin
                while data = sock.read(1024)
                  conn << data
                end
              rescue => e
                puts "#{e.class} exception: #{e.message} - closing socket."
                e.backtrace.each { |l| puts "\t" + l }
                sock.close
              end
              puts "#{conn}: No more data"
            end
          rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET, Errno::EPIPE,
                     Errno::ETIMEDOUT, Errno::EHOSTUNREACH => ex
            puts "Error accepting SSLSocket: #{ex.class}: #{ex.to_s}"
            retry
          rescue => e
            puts "#{e.class}: #{e.message}"
          end
        end
      end
      @reactor.run
    end

    # builds a new SSLContext suitable for use in 'h2' connections
    #
    def create_ssl_context **opts
      ctx                  = OpenSSL::SSL::SSLContext.new
      ctx.ca_file          = opts[:ca_file] if opts[:ca_file]
      ctx.ca_path          = opts[:ca_path] if opts[:ca_path]
      ctx.cert             = context_cert opts[:cert]
      ctx.ciphers          = opts[:ciphers] || OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
      ctx.extra_chain_cert = context_extra_chain_cert opts[:extra_chain_cert]
      ctx.key              = context_key opts[:key]
      ctx.options          = opts[:options] || OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options]
      ctx.servername_cb    = @sni_callback
      ctx.ssl_version      = :TLSv1_2
      context_ecdh ctx
      context_set_protocols ctx
      ctx
    end

    private

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
