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

class TCPServeSingleConnection
  def initialize(server, port, &block)
    dts = TCPServer.new(server, port)  
    @th = Thread.start {
      s=dts.accept
      block.call(s)
      s.close
      dts.close
    }
  end

  def join
    @th.join
  end
end

class TCPServeSingleDataSender < TCPServeSingleConnection
  def initialize(server, port, data)
    super(server, port) { |s|
      s.write(data)
    }
  end
end

class TCPServeSingleDataReciever < TCPServeSingleConnection
  def initialize(server, port, maxlen)
    super(server, port) { |s|
      @datarecv=s.recv(100)
    }
  end
  def join
    super
    return @datarecv
  end
end


def TCPSingleDataRecv(server, port, maxlen)
  streamSock = TCPSocket.new(server, port)  
  data = streamSock.recv( maxlen )  
  streamSock.close
  return data
end


def TCPSingleDataSend(server, port, data)
  streamSock = TCPSocket.new(server, port)  
  streamSock.write( data )  
  streamSock.close
end


# The following function is mostly inspired from the code snippet published 
# by Scott Bronson on http://gist.github.com/287675
# rewritten using Test::Unit::Assertions to better fit in tests
def assert_equal_objects(expected, actual, message=nil, path='')
  if path=='' then
    prefix="Objects differ:"
  else
    prefix="Objects differ at #{path}:"
  end
  if expected.kind_of?(Hash)
    extraexpectedkeys = expected.keys - actual.keys
    full_message = build_message(message, "#{prefix} extra keys in expected: <?>.\n", extraexpectedkeys)
    assert_block(full_message) { extraexpectedkeys.length == 0 }
    extraactualkeys = actual.keys - expected.keys
    full_message = build_message(message, "#{prefix} extra keys in actual: <?>.\n", extraactualkeys)
    assert_block(full_message) { extraactualkeys.length == 0 }
    expectedkeys=expected.keys
    begin
      expectedkeys.sort!
    rescue NoMethodError
    end
    expectedkeys.each do |key|
      assert_equal_objects expected[key], actual[key], message, path.dup << build_message(nil,"[?]",key).to_s
    end
  elsif (expected.kind_of?(Enumerable) && !expected.kind_of?(String)) && (actual.kind_of?(Enumerable) && !actual.kind_of?(String))
    full_message = build_message(message, "#{prefix} expected has #{expected.length} and actual has #{actual.length} items.\n<?> expected but was\n<?>.\n", expected, actual)
    assert_block(full_message) { expected.length == actual.length }
    (0..expected.length).each do |i|
      assert_equal_objects expected[i], actual[i], message, path.dup << "[#{i}]"
    end
  elsif expected != actual
    full_message = build_message(message, "#{prefix}\n<?> expected but was\n<?>.\n", expected, actual)
    assert_block(full_message) { false }
  end
end

# vim:sw=2:sta:et:
