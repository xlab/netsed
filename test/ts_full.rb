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
# This test suite run all available tests named tc_*.rb
#
# It also makes sure the tests are run from the directory where the script is
# ( hopefully test/ in netsed source directory, so that netsed binary can be 
# found in ../netsed ).
#
# :main:ts_full.rb

require 'test/unit'

Dir.chdir(File.dirname(__FILE__))
require './test_helper'

Dir .glob('tc_*.rb') { |f|
  #puts "adding #{f}"
  require "./" + f
}

# vim:sw=2:sta:et:
