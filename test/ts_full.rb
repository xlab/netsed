#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# this test suite run all available test named ts_*.rb

require 'test/unit'

Dir.chdir(File.dirname(__FILE__))
require 'test_helper'

Dir .glob('tc_*.rb') { |f|
  #puts "adding #{f}"
  require f
}

# vim:sw=2:sta:et:
