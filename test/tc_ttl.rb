#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this file implements checks for the TTL (time-to-live) feature of netsed rules in the class TC_TTLTest.

require 'test/unit'
require './test_helper'

# Test Case for netsed TTL (time-to-live) feature
class TC_TTLTest < Test::Unit::TestCase
  # def setup
  # end

  # def teardown
  # end

  # Check first occurrence
  def test_TTL_1
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and andrew'
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)

    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, ['s/andrew/mike/1'])

    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end

  # Check 20 occurrences
  def test_TTL_20
    datasent   = '% %% %%% %%%% %%%%% %%%%%% %%%%%%%'
    dataexpect = '/ // /// //// ///// /////% %%%%%%%'
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)

    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, ['s/%%/%2f/20'])

    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)

    serv.join
    netsed.kill

    assert_equal(dataexpect, datarecv)
  end

  # Check first occurrence in several connections: the TTL is not global.
  def test_TTL_1_byConnections
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and andrew'

    netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, ['s/andrew/mike/1'])

    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)
    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)
    serv.join

    assert_equal(dataexpect, datarecv, 'At first connection')

    # once again
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)
    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)
    serv.join

    assert_equal(dataexpect, datarecv, 'At second connection')
  ensure
    netsed.kill
  end

end

# vim:sw=2:sta:et:
