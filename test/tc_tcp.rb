#!/usr/bin/ruby
# netsed Unit::Tests
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
# 
# this file implements checks for netsed  behaviour regarding tcp connections.
# * TC_TCPTest run the tests on IPv4.
# * TC_TCPTest6 is a generated class which rerun all the tests on IPv6.
#

require 'test/unit'
require './test_helper'

# Test Case for TCP
#
# Note: it runs netsed in the setup to allow to rerun all tests in a single
# netsed invocation by test_group_all
class TC_TCPTest < Test::Unit::TestCase
  CONFIG={:SERVER=>LH_IPv4,:OPTIONS=>'-4'}
  
  # Launch netsed
  def setup
    #puts self.class::CONFIG[:SERVER]
    @netsed = NetsedRun.new('tcp', LPORT, self.class::CONFIG[:SERVER], RPORT, ['s/andrew/mike'], self.class::CONFIG[:OPTIONS])
  end

  # Kill netsed
  def teardown
    @netsed.kill
  end

  # Check when server disconnects
  def test_case_01_ServerDisconnect
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'
    serv = TCPServeSingleDataSender.new(self.class::CONFIG[:SERVER], RPORT, datasent)
    datarecv = TCPSingleDataRecv(self.class::CONFIG[:SERVER], LPORT, 100)
    serv.join
    assert_equal(dataexpect, datarecv)
  end

  # Check when there is no server
  def test_case_02_NoServer
    datarecv = TCPSingleDataRecv(self.class::CONFIG[:SERVER], LPORT, 100)
    assert_equal('', datarecv)
  end

  # Check when the client sends the data
  def test_case_03_ClientSendData
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'

    serv = TCPServeSingleDataReciever.new(self.class::CONFIG[:SERVER], RPORT, 100)
    TCPSingleDataSend(self.class::CONFIG[:SERVER], LPORT, datasent)
    datarecv=serv.join
    assert_equal(dataexpect, datarecv)
  end

  # Check when both client and server send data
  def test_case_04_Chat
    datasent = ['client: bla bla andrew', 'server: ok andrew ok']
    dataexpect = ['client: bla bla mike', 'server: ok mike ok']
    datarecv = []
    serv = TCPServeSingleConnection.new(self.class::CONFIG[:SERVER], RPORT) { |s|
      datarecv[0] = s.recv( 100 )
      s.write(datasent[1])
    }
    streamSock = TCPSocket.new(self.class::CONFIG[:SERVER], LPORT)  
    streamSock.write( datasent[0] )  
    datarecv[1] = streamSock.recv( 100 )
    streamSock.close
    serv.join

    assert_equal_objects(dataexpect, datarecv)
  end

  # Check when there are multiple clients
  def test_case_05_ServeMultiple
    datasent = ['0: bla bla andrew', '1: ok andrew ok']
    dataexpect = ['0: bla bla mike', '1: ok mike ok']
    # open server
    datarecv=[]
    serv = TCPServeMultipleConnection.new(self.class::CONFIG[:SERVER], RPORT, 2) { |s, j|
      #puts "Thread #{j} accepted connection"
      datarecv[j] = s.recv( 100 )
    }

    # open connection to 2 server simultaneously
    cs=[]
    for i in 0..1 do
      #puts "client #{i}"
      cs[i] = TCPSocket.new(self.class::CONFIG[:SERVER], LPORT)
      sleep 0.001 # sleep to ensure connection order on server thread
    end
    # write to each connections
    for i in 0..1 do
      cs[i].write( datasent[i] )
    end
    cs.each {|s| s.close}

    serv.join

    assert_equal_objects(dataexpect, datarecv)
  end


  # Check that netsed is still here for the test_group_all call ;)
  def test_case_zz_LastCheck
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'
    serv = TCPServeSingleDataSender.new(self.class::CONFIG[:SERVER], RPORT, datasent)
    datarecv = TCPSingleDataRecv(self.class::CONFIG[:SERVER], LPORT, 100)
    serv.join
    assert_equal(dataexpect, datarecv)
  end

  # Rerun all 'test_case*' methods in one test to allow check that netsed is not crashed by any test.
  def test_group_all
    tests = self.class::get_all_test_case
    tests.sort.each { |test|
      __send__(test)
    }
  end

private

  # Returns all 'test_case*' methods in the class
  def self.get_all_test_case
    method_names = public_instance_methods(true)
    return method_names.delete_if {|method_name| method_name !~ /^test_case./}
  end

end

# Manually generate class TC_TCPTest6
# to rerun all TCP tests with IPv6 localhost,
# inspired by http://www.ruby-forum.com/topic/204730.
TC_TCPTest6=Class.new(TC_TCPTest)
TC_TCPTest6.const_set(:CONFIG, {:SERVER=>LH_IPv6,:OPTIONS=>'-6'})
# vim:sw=2:sta:et:
