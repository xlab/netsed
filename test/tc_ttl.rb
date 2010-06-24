#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this tests check the TTL (time-to-live) feature on netsed rules

require 'test/unit'
require 'test_helper'

class TC_TTLTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  def TCP_TTL_basic(server, port1, port2)
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and andrew'
    serv = TCPServeSingleDataSender.new(server, port2, datasent)

    netsed = NetsedRun.new('tcp', port1.to_s, server, port2.to_s, 's/andrew/mike/1')

    datarecv = TCPSingleDataRecv(server, port1, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end


  def test_netsed
    TCP_TTL_basic(LH_IPv4, 20000, 20001)
  end

  def test_netsed6
    TCP_TTL_basic(LH_IPv6, 20000, 20001)
  end

end

# vim:sw=2:sta:et:
