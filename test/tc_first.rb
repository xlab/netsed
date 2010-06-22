#!/usr/bin/ruby
# test netsed using sockets

require 'test/unit'
require 'socket'

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
    Process.kill('TERM', @pipe.pid)
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

class TC_FirstTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  def TCPSingleDataServeSendTest(server, port)
    datasent=Time.now.to_s
    serv = TCPServeSingleDataSender.new(server, port, datasent)

    datarecv = TCPSingleDataRecv(server, port, 100)

    serv.join

    assert(datasent == datarecv, 'data received does not correspond to data sent.')
  end

  def TCPSingleDataServeSendNetsed(server, port1, port2)
    datasent=Time.now.to_s
    serv = TCPServeSingleDataSender.new(server, port2, datasent)

    netsed = NetsedRun.new('tcp', port1.to_s, server, port2.to_s, 's/andrew/mike')

    datarecv = TCPSingleDataRecv(server, port1, 100)

    serv.join
    netsed.kill

    assert(datasent == datarecv, 'data received does not correspond to data sent.')
  end


  def test_socket
    TCPSingleDataServeSendTest('127.0.0.1', 20002)
  end

  def test_socket6
    TCPSingleDataServeSendTest('::1', 20002)
  end

  def test_netsed
    TCPSingleDataServeSendNetsed('127.0.0.1', 20000, 20001)
  end
  def test_netsed6
    TCPSingleDataServeSendNetsed('::1', 20000, 20001)
  end
end

# vim:sw=2:sta:et:
