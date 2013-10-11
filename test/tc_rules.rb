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
# this file implements checks for netsed rules in class TC_RuleTest

require 'test/unit'
require './test_helper'

# Test Case for netsed rules
class TC_RuleTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  # General rule checker method used by actual tests
  # - _datasent_ are send by a server, 
  # - _dataexpect_ are the corresponding expected data on the client side,
  # - _rules_ is a set of rules passed to netsed.
  def TCP_RuleCheck(datasent, dataexpect, rules)
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)

    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, rules)

    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end

  # Check a basic rule.
  def test_basic_rule
    TCP_RuleCheck('test andrew is there' ,"test mike\0\0 is there", ['s/andrew/mike%00%00'])
  end

  # Check single char replacement.
  #
  # Note: This one fail without commit 387a9d46387e2488efac08931b0aab57c7594aa2,
  # it returns "b b ba bab baba" !!
  def test_smallpattern_rule
    TCP_RuleCheck('a a aa aaa aaaa' ,"b b bb bbb bbbb", ['s/a/b'])
  end

  # Check with 2 rules.
  def test_chain_2_rule
    TCP_RuleCheck('test andrew is there' ,'test mike is here', ['s/andrew/mike', 's/there/here'])
  end

  # Check traditionally delimited rules
  def test_traddelim_rule
    TCP_RuleCheck('a a aa aaa aaaa' ,"b b bb bbb bbbb", ['s/a/b/'])
  end

  # General rule checker method in chat mode
  # - _datasent_ is an array of data to sent 0:client 1:server, 
  # - _dataexpect_ are the corresponding expected data on the other side,
  # - _rules_ is a set of rules passed to netsed.
  def TCP_RuleChatCheck(datasent, dataexpect, rules)
    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, rules)
    datarecv = []
    serv = TCPServeSingleConnection.new(SERVER, RPORT) { |s|
      datarecv[0] = s.recv( 100 )
      s.write(datasent[1])
    }
    streamSock = TCPSocket.new(SERVER, LPORT)  
    streamSock.write( datasent[0] )  
    datarecv[1] = streamSock.recv( 100 )
    streamSock.close
    serv.join

    netsed.kill

    assert_equal_objects(dataexpect, datarecv)
  end

  # Check direction rules
  # tests based on tcp chat: test_case_04_Chat
  def test_direction_rule
    TCP_RuleChatCheck(
      ['client: bla bla Rilke Proust', 'server: ok Proust ok Rilke'],
      ['client: bla bla Proust Proust', 'server: ok Rilke ok Rilke'],
      ['s/Rilke/Proust/o', 's/Proust/Rilke/i'])
  end

  # Check direction+ttl rules
  # tests based on tcp chat: test_case_04_Chat
  def test_direction_ttl_rule
    TCP_RuleChatCheck(
      ['client: bla bla Rilke Rilke', 'server: ok Proust ok Proust'],
      ['client: bla bla Proust Rilke', 'server: ok Rilke ok Proust'],
      ['s/Rilke/Proust/o1', 's/Proust/Rilke/i1'])
  end

end

# vim:sw=2:sta:et:
