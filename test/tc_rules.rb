#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this file implements checks for netsed rules in class TC_RuleTest

require 'test/unit'
require 'test_helper'

# Test Case for netsed rules
class TC_RuleTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  # General rule checker method used by actual tests
  # - _datasent_ are send by a server, 
  # - _dataexpect_ are the corresponding expected data on the client side,
  # - _*rules_ is a set of rules passed to netsed.
  def TCP_RuleCheck(datasent, dataexpect, *rules)
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)

    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, *rules)

    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end

  # Check a basic rule.
  def test_basic_rule
    TCP_RuleCheck('test andrew is there' ,"test mike\0\0 is there", 's/andrew/mike%00%00')
  end

  # Check single char replacement.
  #
  # Note: This one fail without commit 387a9d46387e2488efac08931b0aab57c7594aa2,
  # it returns "b b ba bab baba" !!
  def test_smallpattern_rule
    TCP_RuleCheck('a a aa aaa aaaa' ,"b b bb bbb bbbb", 's/a/b')
  end

  # Check with 2 rules.
  def test_chain_2_rule
    TCP_RuleCheck('test andrew is there' ,'test mike is here', 's/andrew/mike', 's/there/here')
  end

end

# vim:sw=2:sta:et:
