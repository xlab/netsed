#!/usr/bin/ruby
# netsed Unit::Tests
# (c) 2010 Julien Viard de Galbert <julien@silicone.homelinux.org>
#
# This test suite run all available tests named tc_*.rb
#
# It also makes sure the tests are run from the directory where the script is
# ( hopefully test/ in netsed source directory, so that netsed binary can be 
# found in ../netsed ).
#
# :main:ts_full.rb

require 'test/unit'

Dir.chdir(File.dirname(__FILE__))
require 'test_helper'

Dir .glob('tc_*.rb') { |f|
  #puts "adding #{f}"
  require f
}

# vim:sw=2:sta:et:
