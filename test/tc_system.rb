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
# this file implements checks for netsed system behaviour in class TC_SystemTest

require 'test/unit'
require './test_helper'
require 'thread'

# Test Case for netsed system behaviour
class TC_SystemTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  # Check if netsed can take high CPU load.
  #
  # Note: case of debian bug #586037.
  #
  # Actually running it against the old version blocks.
  # Old netsed does not have the SIGINT handling (you have to kill it manually)
  # but the test detects the load.
  def test_TightNonBlockingLoop
    mutex=Mutex.new
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and andrew'
    serv = TCPServeSingleConnection.new(SERVER, RPORT) { |s|
      # to ensure the server stays open
      mutex.synchronize do
      end
    }
    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, ['s/andrew/mike/1'])

    cpuload = 0
    # ensure both server and client have open socket to netsed 
    # and see if it reaches a high load
    mutex.synchronize do
      streamSock = TCPSocket.new(SERVER, LPORT)

      # wait for the cpu load to rise
      sleep 1
      # check netsed cpu usage
      # it's the child process that will take the cpu...
      ret = `ps --ppid #{netsed.pid} -o %cpu h`
      #puts "#{netsed.pid}: #{ret}"
      cpuload = ret.to_i

      streamSock.close
    end

    serv.join
    netsed.kill

    assert_operator(cpuload, :<, 50, 'netsed child process taking too much CPU.')
  end

end

# vim:sw=2:sta:et:
