#
# sb2dot - a sandbox binary profile to dot convertor for iOS 9 and OS X 10.11
# Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>
#    uses and extends code from Dionysus Blazakis with his permission
#
# module: redis.py
# task: regular expression disassembly
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

import struct
import cStringIO
from minigraph import *

def hexdump(_str):
    cnt = len(_str)
    
    for i in range(cnt):
        c = ord(_str[i])
        print ("%02x " % ord(_str[i])),
        if (c < 32):
            c = 0x2e
        if (c > 127):
            c = 0x2e
        if ((i+1) % 16 == 0):
            print ""
        
    print ""
    for i in range(cnt):
        c = ord(_str[i])
        if (c < 32):
            c = 0x2e
        if (c > 127):
            c = 0x2e
        print ("%c" % c),
        if ((i+1) % 16 == 0):
            print ""
    print ""
    print ""


class CharMask(object):
    
  def __init__(self, mask=None):
    self.mask = {}
    self.invert = False
    for i in range(256):
      self.mask[i] = False
      
  def addFromTo(self, f, t):
    f = ord(f)
    t = ord(t)
    if f > t:
      t = t + 256
      self.invert = True
      
    for i in range(f, t+1):
      self.mask[i % 256] = True
  
  def invertmask(self):
    mask = {}
    for i in range(256):
      mask[i] = not self.mask[i]
    return mask

  def __repr__(self):
    if self.invert:
      mask = self.invertmask()
      prefix = "^"
    else:
      mask = self.mask
      prefix = ""
    
    pattern = ""
    i = 0
    while True:
      # search until next allowed pattern
      while i < 256 and mask[i] == False:
        i = i + 1
      if i == 256:
        break
      
      f = i
      t = f
      while i < 256 and mask[i] == True:
        t = i
        i = i + 1
      
      #print f,t
      if f == t:
        if f == ord("-"):
          pattern = "-" + pattern
        else:
          pattern = pattern + chr(f)
      elif f == t - 1:
        pattern = pattern + chr(f) + chr(t)
      else:
        pattern = pattern + chr(f) + "-" + chr(t)
      
    
    return "[" + prefix + pattern + "]"


def maybe_escape(s):
  if s in '^$.?*[]()':
    return '\\' + s
  else:
    return s


def reToGraph(re):
  f = cStringIO.StringIO(re)
  version = struct.unpack('>I', f.read(4))
  #print "version: %08x" % version[0]
  if version[0] != 3:
    print 'This is an old regular expression. Cannot handle this.'
    return None

  # TODO: need to find the bug that sometimes regular expression decoding results in NULL
  #hexdump(re)

  g = MiniGraph()
  mlen = struct.unpack('<H', f.read(2))
  mlen = mlen[0]
  idx = 0
  while True:
    idx = f.tell()-6
    if mlen == idx:
        break
            
    typ = ord(f.read(1))
    if typ & 0xf == 10:
        typ = 10
    if typ == 0x2f:
      target = struct.unpack('<H', f.read(2))
      g.addEdge(idx, target[0])
      g.addEdge(idx, idx+3)
      g.setTag(idx, (typ, None))
    elif typ == 0x0a:
      target = struct.unpack('<H', f.read(2))
      g.addEdge(idx, target[0])
      #g.addEdge(idx, idx+3)
      g.setTag(idx, (typ, None))
    elif typ == 0x15:
      # unsure overread
      f.read(1)
      g.setTag(idx, (typ, None))
    elif typ == 0x19:
      g.addEdge(idx, idx+1)
      g.setTag(idx, (0x100, "^"))
    elif typ == 0x29:
      g.addEdge(idx, idx+1)
      g.setTag(idx, (0x100, "$"))
    elif typ == 0x02:
      g.addEdge(idx, idx+2)
      g.setTag(idx, (0x100, maybe_escape(chr(ord(f.read(1)) & 0xff))))
    elif typ == 0x09:
      g.addEdge(idx, idx+1)
      g.setTag(idx, (0x100, "."))
    elif (typ & 0xf) == 0xb:
      cmask = CharMask()
      
      cnt = typ >> 4
      for i in range(cnt):
          c1 =  f.read(1)
          c2 =  f.read(1)
          cmask.addFromTo(c1, c2)

      g.addEdge(idx, idx+1+cnt*2)
      g.setTag(idx, (0x100, str(cmask)))
    else:
      print "ILLEGAL TYPE"
      print "idx: %08x" % idx
      print "typ: %02x" % typ
      break
  
  return g

def eliminateDummyEdges(g):
    
    for u, adjs in g.edges.items():
        
        utag = g.getTag(u)
        if utag == None:
            continue
        t,d = utag
        if t == 0x2f:
            for v in adjs:
                vtag = g.getTag(v)
                if vtag != None:
                    t,d = vtag
                    if t == 0x0a:
                        edges = list(g.edges[v])
                        for e in edges:
                            g.addEdge(u, e)
                        g.removeNode(v)                    


def graphToRegEx(g):
  # Merge adjacents and pattern match for RE ops
  done = False
  #g.pprint()
  eliminateDummyEdges(g)
  #g.pprint()
  while not done:
    done = True
    for u, adjs in g.edges.items():
      utag = g.getTag(u)
      for v in adjs:
        if g.mergeIfPossible(u, v):
          done = False
          break
      if not done:
        break

  done = False
  

  while not done:
    done = True
    for u, adjs in g.edges.items():
      utag = g.getTag(u)
      
      # Get rid of "ACCEPT" nodes
      if utag is not None and utag[0] == 0x15:
        g.removeNode(u)
        done = False
        break
        
      # Try to match *
      if utag is not None and utag[0] in [0x2F] and len(adjs) == 2:
        v_left = list(adjs)[0]
        v_right = list(adjs)[1]
        v_lefttag = g.getTag(v_left)
        v_righttag = g.getTag(v_right)
        

        if v_lefttag is not None and v_lefttag[0] == 0x100:
          if g.edges[v_left] == set([u]) and g.redges[v_left] == set([u]):       
            g.removeEdge(u, v_left)
            g.removeNode(v_left)
            g.setTag(u, (0x100, '(' + v_lefttag[1] + ')*'))
            done = False
            break
          elif u in g.edges[v_left] and len(g.redges[v_left]) == 2 and \
               u in g.redges[v_left]:
            entry = list(g.redges[v_left] - set([u]))[0]
            g.removeEdge(entry, v_left)
            g.removeEdge(u, v_left)
            g.removeNode(v_left)
            g.addEdge(entry, u)
            g.setTag(u, (0x100, '(' + v_lefttag[1] + ')+'))
            done = False
            break
          
        if v_righttag is not None and v_righttag[0] == 0x100:
          if g.edges[v_right] == set([u]) and g.redges[v_right] == set([u]):
            g.removeEdge(u, v_right)
            g.removeNode(v_right)
            g.setTag(u, (0x100, '(' + v_righttag[1] + ')*'))
            done = False
            break
          elif u in g.edges[v_right] and len(g.redges[v_right]) == 2 and \
               u in g.redges[v_right]:
            entry = list(g.redges[v_right] - set([u]))[0]
            g.removeEdge(entry, v_right)
            g.removeEdge(u, v_right)
            g.removeNode(v_right)
            g.addEdge(entry, u)
            g.setTag(u, (0x100, '(' + v_righttag[1] + ')+'))
            done = False
            break

      # Try to match | and ?
      if utag is not None and utag[0] in [0x2F] and len(adjs) == 2:
        v_left = list(adjs)[0]
        v_right = list(adjs)[1]
        v_lefttag = g.getTag(v_left)
        v_righttag = g.getTag(v_right)

        # Match |
        if v_lefttag is not None and v_lefttag[0] == 0x100 and \
           v_righttag is not None and v_righttag[0] == 0x100:
          vl_next = g.edges[v_left]
          vr_next = g.edges[v_right]

          if len(vl_next) <= 1 and len(vr_next) <= 1 and \
             vl_next == vr_next:
            g.removeEdge(u, v_left)
            g.removeEdge(u, v_right)
            if len(vl_next) == 1:
              join_node = list(vl_next)[0]
              g.addEdge(u, join_node)
            g.removeNode(v_left)
            g.removeNode(v_right)
            g.setTag(u, (0x100, '(' + v_lefttag[1] + '|' + v_righttag[1] + ')'))
            done = False
            break

        # Match ?
        if v_lefttag is not None and v_lefttag[0] == 0x100 and \
           v_righttag is not None:
          vl_next = g.edges[v_left]
          if len(vl_next) == 1 and list(vl_next)[0] == v_right:
            g.removeEdge(u, v_left)
            g.removeEdge(u, v_right)
            g.addEdge(u, v_right)
            g.removeNode(v_left)
            g.removeNode(v_right)
            g.setTag(u, (0x100, '(' + v_lefttag[1] + ')?'))
            done = False
            break

        if v_lefttag is not None and \
           v_righttag is not None and v_righttag[0] == 0x100:
          vr_next = g.edges[v_right]
          if len(vr_next) == 1 and list(vr_next)[0] == v_left:
            g.removeEdge(u, v_left)
            g.removeEdge(u, v_right)
            g.addEdge(u, v_left)
            g.removeNode(v_left)
            g.removeNode(v_right)
            g.setTag(u, (0x100, '(' + v_righttag[1] + ')?'))
            done = False
            break

      if utag is not None and utag[0] == 0x31:
        for v in g.edges[u]:
          for uu in g.redges[u]:
            g.addEdge(uu, v)
        g.removeNode(u)
        done = False
        break

      # Merge constants if possible
      for v in adjs:
        if g.mergeIfPossible(u, v):
          done = False
          break
      if not done:
        break

  #g.pprint()
  if len(g.nodes) == 1:
    return g.getTag(list(g.nodes)[0])[1]
  else:
    return None
