#!/usr/bin/ruby
# -*- coding: utf-8 -*-
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
# this file implements checks for netsed  behaviour regarding udp 'connections'.
# * TC_UDPTest run the tests on IPv4.
# * TC_UDPTest6 is a generated class which rerun all the tests on IPv6.
#

require 'test/unit'
require './test_helper'

# Test Case for UDP
#
# Note: it runs netsed in the setup to allow to rerun all tests in a single
# netsed invocation by test_group_all
class TC_UDPTest < Test::Unit::TestCase
  SERVER=LH_IPv4
  
  # Launch netsed
  def setup
    #puts self.class::SERVER
    @netsed = NetsedRun.new('udp', LPORT, self.class::SERVER, RPORT, ['s/andrew/mike'])
  end

  # Kill netsed
  def teardown
    @netsed.kill
  end

  # Check single datagram transmission
  def test_case_01_single
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'
    serv = UDPSocket.new
    serv.bind(self.class::SERVER, RPORT)
    UDPSingleDataSend(self.class::SERVER, LPORT, datasent)
    datarecv = serv.recv( 100 )
    serv.close
    assert_equal(dataexpect, datarecv)
  end

  # Check when both client and server send datagrams
  def test_case_02_Chat
    datasent = ['client: bla bla andrew', 'server: ok andrew ok']
    dataexpect = ['client: bla bla mike', 'server: ok mike ok']
    datarecv = []
    serv = UDPSocket.new
    serv.bind(self.class::SERVER, RPORT)
    dataSock = UDPSocket.new
    dataSock.connect(self.class::SERVER, LPORT)
    dataSock.write( datasent[0] )  
    datarecv[0],senderaddr = serv.recvfrom( 100 )
    serv.send(datasent[1], 0, senderaddr[3], senderaddr[1])
    datarecv[1] = dataSock.recv( 100 )
    dataSock.close
    serv.close

    assert_equal_objects(dataexpect, datarecv)
  end

  # Check when there are multiple clients
  def test_case_03_ServeMultiple
    datasent = ['0: bla bla andrew', '1: ok andrew ok', '2: bla andrew', '3: andrew ok']
    dataexpect = ['0: bla bla mike', '1: ok mike ok', '2: bla mike', '3: mike ok']
    datarecv=[]
    # open server
    serv = UDPSocket.new
    serv.bind(self.class::SERVER, RPORT)
    dataSock = UDPSocket.new
    dataSock.connect(self.class::SERVER, LPORT)
    dataSock.write( datasent[0] )  
    datarecv[0],senderaddr = serv.recvfrom( 100 )
    serv.send(datasent[1], 0, senderaddr[3], senderaddr[1])
    datarecv[1] = dataSock.recv( 100 )

    cs=[]
    for i in 0..1 do
      cs[i] = UDPSocket.new
      cs[i].connect(self.class::SERVER, LPORT)
      cs[i].write( datasent[i] )
    end
    for i in 0..1 do
      datarecv[i],senderaddr = serv.recvfrom( 100 )
      serv.send(datasent[i+2], 0, senderaddr[3], senderaddr[1])
    end
    for i in 0..1 do
      datarecv[i+2] = cs[i].recv( 100 )
      cs[i].close
    end
    serv.close

    assert_equal_objects(dataexpect, datarecv)
  end


  # Check that netsed is still here for the test_group_all call ;)
  def test_case_zz_LastCheck
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'
    serv = UDPSocket.new
    serv.bind(self.class::SERVER, RPORT)
    UDPSingleDataSend(self.class::SERVER, LPORT, datasent)
    datarecv = serv.recv( 100 )
    serv.close
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

# Manually generate class TC_UDPTest6
# to rerun all UDP tests with IPv6 localhost,
# inspired by http://www.ruby-forum.com/topic/204730.
#TC_UDPTest6=Class.new(TC_UDPTest)
#TC_UDPTest6.const_set(:SERVER, LH_IPv6)
# for some reasons UDPSocket.connect fails with IPv6 addr :(

# vim:sw=2:sta:et:
