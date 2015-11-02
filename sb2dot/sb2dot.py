#!/usr/bin/env python

#
# sb2dot - a sandbox binary profile to dot convertor for iOS 9 and OS X 10.11
# Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>
#    uses and extends code from Dionysus Blazakis with his permission
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from __future__ import with_statement
import struct
import sys
import binascii
import pprint
import os
import redis
from minigraph import *
from filters import *
from outputdot import *

def load_op_names(fn):
  global OP_TABLE_COUNT
  f = open(fn, 'r')
  ops = [s.strip() for s in f.readlines()]
  if ops[-1] == '':
    ops = ops[:-1]
  OP_TABLE_COUNT = len(ops)
  return ops

def parse_filternode(g, f, offset, re_table):
  if g.getTag(offset * 8) is not None:
    return

  f.seek(offset * 8)
  is_terminal = ord(f.read(1)) == 1

  if is_terminal:
    f.read(1) # padding
    result, = struct.unpack('<H', f.read(2))
    tag = Terminal(result)
    g.setTag(offset * 8, tag)
  else:
    filter, filter_arg, match, unmatch = struct.unpack('<BHHH', f.read(7))
    #print "rule: %d %d %d %d" % (filter, filter_arg, match, unmatch)
    tag = get_filter(f, re_table, filter, filter_arg)
    #print tag
    g.setTag(offset * 8, tag)
    g.addEdge(offset * 8, match * 8)
    g.addEdge(offset * 8, unmatch * 8)

    if g.getTag(match * 8) is None:
      parse_filternode(g, f, match, re_table)
    if g.getTag(unmatch * 8) is None:
      parse_filternode(g, f, unmatch, re_table)



def parse_optable(profile_name, f, op_table):
  global regex_table
  global sbops
  
  non_default_ops = []
  non_default_offs = {}
  names = {}
  clean_names = {}
  cnt = 0
  default_op = op_table[0]
  for op_idx, op_offset in enumerate(op_table):
    if op_offset != default_op:      
      if names.has_key(op_offset):
          names[op_offset] = names[op_offset] + " " + sbops[cnt]
          clean_names[op_offset] = clean_names[op_offset] + "\n" + sbops[cnt]
      else:
          names[op_offset] = sbops[cnt]
          clean_names[op_offset] = sbops[cnt]
      if not non_default_offs.has_key(op_offset):
          non_default_ops.append((cnt,op_idx))
      non_default_offs[op_offset] = 1
      
    cnt = cnt + 1
    
  cnt = 0
  g = MiniGraph()
  for op_idx, op_offset in enumerate(op_table):
    #print "%u: %u" % (op_idx, op_offset)
    parse_filternode(g, f, op_offset, regex_table)
    cnt = cnt + 1

  dump_to_dot(g, default_op, "default", "default", profile_name)
  for i, op_idx in non_default_ops:
    
    dump_to_dot(g, op_table[op_idx], names[op_table[op_idx]], clean_names[op_table[op_idx]], profile_name)
  

def usage():
  print 'usage:'
  print '    sb2dot sbops.txt sbprofile.bin'
  print
  print '    This will turn a binary sandbox profile into a nice .dot graph.'
  sys.exit(-1)

if len(sys.argv) < 3:
  usage()

sbops = load_op_names(sys.argv[1])
sbprofile_path = sys.argv[2]

with open(sbprofile_path, 'rb') as f:
    
  # read in short header
  flags, re_table_offset, re_table_count = struct.unpack('<HHH', f.read(6))

  # read in the regex table
  f.seek(re_table_offset * 8)
  re_table = struct.unpack('<%dH' % re_table_count, f.read(2 * re_table_count))

  print "[+] loading and decoding regular expressions"
  regex_table = []
  for offset in re_table:
    #print "position %08x" % (offset *8)
    f.seek(offset * 8)
    re_count = struct.unpack('<I', f.read(4))[0]
    #print "len: %08x" % (re_count)
    raw = f.read(re_count)
    g = redis.reToGraph(raw)
    re = redis.graphToRegEx(g)
    if re == None:
        print "[!] ERROR: regex disassembler failed disassembling a regular expression - TODO"
    #die()
    regex_table.append(re)

  # now read the profile(s)
  if flags == 0x8000:
    # this is a profile collection
    print '[+] found: profile collection'

    f.seek(3*2)
    collection_count, = struct.unpack('<H', f.read(2))
    print '[i] collection count %u' % collection_count
    
    for ic in range(collection_count):
      # read each operation in
      f.seek(4 * 2 + ic * (2 * (2 + OP_TABLE_COUNT)))
      profilename_offset, innerflags = struct.unpack('<HH', f.read(4))
      op_table = struct.unpack('<%dH' % OP_TABLE_COUNT, f.read(2 * OP_TABLE_COUNT))
      
      f.seek(profilename_offset * 8)
      count, = struct.unpack('<I', f.read(4))
      profile_name = f.read(count).strip('\x00')
      print "[+] decoding profile: " + profile_name
      parse_optable(profile_name,f, op_table)
      
  else: # flags are usually 0 (sometimes 1,2)
    # this is a single profile
    print '[+] found: single profile'
    print '[+] decoding profile'

    f.seek(3*2)
    op_table = struct.unpack('<%dH' % OP_TABLE_COUNT, f.read(2 * OP_TABLE_COUNT))
    profile_name = sbprofile_path
    parse_optable(profile_name,f, op_table)
