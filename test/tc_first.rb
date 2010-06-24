#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this fists tests check the helper function in 'test_helper'

require 'test/unit'
require 'test_helper'

class TC_FirstTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  def TCPSingleDataServeSendTest(server, port)
    datasent=Time.now.to_s
    serv = TCPServeSingleDataSender.new(server, port, datasent)

    datarecv = TCPSingleDataRecv(server, port, 100)

    serv.join

    assert(datasent == datarecv, 'data received does not correspond to data sent.')
  end

  def TCPSingleDataServeSendNetsed(server, port1, port2)
    datasent=Time.now.to_s
    serv = TCPServeSingleDataSender.new(server, port2, datasent)

    netsed = NetsedRun.new('tcp', port1.to_s, server, port2.to_s, 's/andrew/mike')

    datarecv = TCPSingleDataRecv(server, port1, 100)

    serv.join
    netsed.kill

    assert(datasent == datarecv, 'data received does not correspond to data sent.')
  end


  def test_socket
    TCPSingleDataServeSendTest(LH_IPv4, 20000)
  end

  def test_socket6
    TCPSingleDataServeSendTest(LH_IPv6, 20000)
  end

  def test_netsed
    TCPSingleDataServeSendNetsed(LH_IPv4, 20000, 20001)
  end

  def test_netsed6
    TCPSingleDataServeSendNetsed(LH_IPv6, 20000, 20001)
  end

end

# vim:sw=2:sta:et:
