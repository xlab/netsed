#!/usr/bin/ruby
# helper function for netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# ---------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
#
# You may also redistribute it or any part of it under the Ruby license to
# better integrate to your ruby scripts.
# The ruby license is available at http://www.ruby-lang.org/en/LICENSE.txt
# ---------------------------------------------------------------------------


require 'socket'

LH_IPv4 = '127.0.0.1'
LH_IPv6 = '::1'


#default values for all test classes
LPORT=20000
RPORT=20001
SERVER=LH_IPv4

# Run a netsed instance with given parameters.
class NetsedRun
  attr_reader :data

  # Launch netsed with given parameters.
  def initialize(proto, lport, rhost, rport, rules, options='')
    @cmd="../netsed #{options} #{proto} #{lport} #{rhost} #{rport} #{rules.join(' ')}"
    @pipe=IO.popen(@cmd)
    @data=''
    @pipe.sync = true
    # waiting for netsed to listen
    begin
      line = @pipe.gets
      @data << line
    end until line =~ /^\[\+\] Listening on port/
  end

  # Kill (INT) and wait netsed exit
  # also returns standard output
  def kill
    Process.kill('INT', @pipe.pid)
    Process.wait(@pipe.pid)
    @data << @pipe.read
    @pipe.close
    return @data
  end

  # Returns netsed PID
  def pid
    @pipe.pid
  end
end

# TCP Server that accept multiple connections
class TCPServeMultipleConnection

  # Creates a thread server on _addr_, _port_
  # the block is called for every accepted connections (up to _nbconnections_)
  # once the block exits, the socket is closed.
  def initialize(addr, port, nbconnections) # :yields: socket, index
    dts = TCPServer.new(addr, port)  
    @th = Thread.start {
      ths=[]
      for i in 0..nbconnections-1 do
        sa=dts.accept
        ths[i] = Thread.start(i, sa) {|j, s|
          yield s,j
          s.close
        }
      end
      ths.each {|tha| tha.join}
      dts.close
    }
  end

  # Wait for the server to complete, it will once all connections are processed.
  def join
    @th.join
  end
end

# TCP Server that accept a single connection
class TCPServeSingleConnection

  # Creates a thread server on _addr_, _port_
  # the block is called for first accepted connection
  # once the block exits, the socket is closed.
  def initialize(addr, port) # :yields: socket
    dts = TCPServer.new(addr, port)  
    @th = Thread.start {
      s=dts.accept
      yield s
      s.close
      dts.close
    }
  end

  # Wait for the server to complete, it will once the connection is processed.
  def join
    @th.join
  end
end

# TCP Server that accept a single connection and sent data to it
class TCPServeSingleDataSender < TCPServeSingleConnection

  # Creates a thread server on _addr_, _port_ that send _data_ on connection,
  # then closes the socket.
  def initialize(addr, port, data)
    super(addr, port) { |s|
      s.write(data)
    }
  end
end

# TCP Server that accept a single connection and receive data from it
class TCPServeSingleDataReciever < TCPServeSingleConnection

  # Creates a thread server on _addr_, _port_ that receive up to _maxlen_
  # on connection, then closes the socket.
  def initialize(addr, port, maxlen)
    super(addr, port) { |s|
      @datarecv=s.recv(maxlen)
    }
  end

  # Wait for the server to complete, and return the received data.
  def join
    super
    return @datarecv
  end
end

# Receive up to _maxlen_ data from a TCP Socket on _addr_,_port_
def TCPSingleDataRecv(addr, port, maxlen)
  streamSock = TCPSocket.new(addr, port)  
  data = streamSock.recv( maxlen )  
  streamSock.close
  return data
end


# Send _data_ to a TCP Socket on _addr_,_port_
def TCPSingleDataSend(addr, port, data)
  streamSock = TCPSocket.new(addr, port)  
  streamSock.write( data )  
  streamSock.close
end


# Send _data_ to a UDP Socket on _addr_,_port_
def UDPSingleDataSend(addr, port, data)
  dataSock = UDPSocket.new
  dataSock.connect(addr, port)  
  dataSock.write( data )  
  dataSock.close
end

# Recursively compare two objects. Asserts if a difference was found.
#
# Note: The function is mostly inspired from the code snippet published 
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
