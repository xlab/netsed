#!/usr/bin/ruby
# helper function for netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>

require 'socket'

LH_IPv4 = '127.0.0.1'
LH_IPv6 = '::1'

class NetsedRun
  attr_reader :data

  def initialize(proto, lport, rhost, rport, *rules)
    @cmd="../netsed #{proto} #{lport} #{rhost} #{rport} #{rules.join(' ')}"
    @pipe=IO.popen(@cmd)
    @data=''
    @pipe.sync = true
    # waiting for netsed to listen
    begin
      line = @pipe.gets
      @data << line
    end until line =~ /^\[\+\] Listening on port/
  end

  def kill
    Process.kill('INT', @pipe.pid)
    Process.wait(@pipe.pid)
    @data << @pipe.read
    @pipe.close
    return @data
  end
end

class TCPServeSingleDataSender
  def initialize(server, port, data)
    dts = TCPServer.new(server, port)  
    @th = Thread.start {
      s=dts.accept
      s.write(data)
      s.close
      dts.close
    }
  end

  def join
    @th.join
  end
end

def TCPSingleDataRecv(server, port, maxlen)
  streamSock = TCPSocket.new(server, port)  
  data = streamSock.recv( maxlen )  
  streamSock.close
  return data
end

# vim:sw=2:sta:et:
