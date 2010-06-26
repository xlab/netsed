#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this tests check several behaviour of netsed regarding tcp connections
#

require 'test/unit'
require 'test_helper'

class TC_TCPTest < Test::Unit::TestCase
  LPORT=20000
  RPORT=20001
  SERVER=LH_IPv4
  
  def setup
    @netsed = NetsedRun.new('tcp', LPORT, SERVER, RPORT, 's/andrew/mike')
  end

  def teardown
    @netsed.kill
  end

  def test_case_01_ServerDisconnect
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)
    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)
    serv.join
    assert_equal(dataexpect, datarecv)
  end

  def test_case_02_NoServer
    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)
    assert_equal('', datarecv)
  end

  # check that netsed is still here for the test_group_all call ;)
  def test_case_zz_LastCheck
    datasent   = 'test andrew and andrew'
    dataexpect = 'test mike and mike'
    serv = TCPServeSingleDataSender.new(SERVER, RPORT, datasent)
    datarecv = TCPSingleDataRecv(SERVER, LPORT, 100)
    serv.join
    assert_equal(dataexpect, datarecv)
  end

  # this method rerun all 'test_case*' methods in one test to allow check that netsed is not crashed by any test.
  def test_group_all
    tests = TC_TCPTest::get_all_test_case
    tests.sort.each { |test|
      __send__(test)
    }
  end

private

  def self.get_all_test_case
    method_names = public_instance_methods(true)
    return method_names.delete_if {|method_name| method_name !~ /^test_case./}
  end

end

# vim:sw=2:sta:et:
