#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this tests check the rules

require 'test/unit'
require 'test_helper'

class TC_RuleTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  def TCP_RuleCheck(server, port1, port2, datasent, dataexpect, *rules)
    serv = TCPServeSingleDataSender.new(server, port2, datasent)

    netsed = NetsedRun.new('tcp', port1.to_s, server, port2.to_s, *rules)

    datarecv = TCPSingleDataRecv(server, port1, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end


  def test_basic_rule
    TCP_RuleCheck(LH_IPv4, 20000, 20001, 'test andrew is there' ,"test mike\0\0 is there", 's/andrew/mike%00%00')
  end

  def test_basic_rule6
    TCP_RuleCheck(LH_IPv6, 20000, 20001, 'test andrew is there' ,"test mike\0\0 is there", 's/andrew/mike%00%00')
  end

  # this one fail without commit 387a9d46387e2488efac08931b0aab57c7594aa2
  # it returns "b b ba bab baba" !!
  def test_smallpattern_rule
    TCP_RuleCheck(LH_IPv4, 20000, 20001, 'a a aa aaa aaaa' ,"b b bb bbb bbbb", 's/a/b')
  end

  def test_smallpattern_rule6
    TCP_RuleCheck(LH_IPv6, 20000, 20001, 'a a aa aaa aaaa' ,"b b bb bbb bbbb", 's/a/b')
  end

  def test_chain_rule
    TCP_RuleCheck(LH_IPv4, 20000, 20001, 'test andrew is there' ,'test mike is here', 's/andrew/mike', 's/there/here')
  end

  def test_chain_rule6
    TCP_RuleCheck(LH_IPv6, 20000, 20001, 'test andrew is there' ,'test mike is here', 's/andrew/mike', 's/there/here')
  end

end

# vim:sw=2:sta:et:
