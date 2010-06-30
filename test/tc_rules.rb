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

  def TCP_RuleCheck(datasent, dataexpect, *rules)
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)

    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, *rules)

    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end

  def test_basic_rule
    TCP_RuleCheck('test andrew is there' ,"test mike\0\0 is there", 's/andrew/mike%00%00')
  end

  # this one fail without commit 387a9d46387e2488efac08931b0aab57c7594aa2
  # it returns "b b ba bab baba" !!
  def test_smallpattern_rule
    TCP_RuleCheck('a a aa aaa aaaa' ,"b b bb bbb bbbb", 's/a/b')
  end

  def test_chain_rule
    TCP_RuleCheck('test andrew is there' ,'test mike is here', 's/andrew/mike', 's/there/here')
  end

end

# vim:sw=2:sta:et:
