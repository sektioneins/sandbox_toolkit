#
# sb2dot - a sandbox binary profile to dot convertor for iOS 9 and OS X 10.11
# Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>
#    uses and extends code from Dionysus Blazakis with his permission
#
# module: minigraph.py
# task: contains simple graph routines
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

class MiniGraph:
  def __init__(self):
    self.nodes = set()
    self.edges = {}
    self.redges = {}
    self.tags = {}

  def setTag(self, u, tag):
    self.tags[u] = tag

  def getTag(self, u):
    return self.tags.get(u)

  def removeEdge(self, u, v):
    self.edges[u].remove(v)
    self.redges[v].remove(u)

  def removeNode(self, u):
    for v in self.redges[u]:
      self.edges[v].remove(u)

    for v in self.edges[u]:
      self.redges[v].remove(u)
 
    self.nodes.remove(u)
    del self.edges[u]
    del self.redges[u]

  def mergeIfPossible(self, u, v):
    if v not in self.edges[u]:
      #print 'Not adjacent'
      return False
    elif self.redges[v] != set([u]):
      #print 'v can be entered via node other than u'
      return False
    elif u not in self.tags or v not in self.tags:
      #print 'untagged nodes cannot be merged'
      return False
    elif (self.tags[u][0] != 0x100 and self.tags[u][0] != 10) or (self.tags[v][0] != 0x100 and self.tags[v][0] != 10):
      #print 'only RE nodes can be merged'
      return False
    else:
      self.edges[u] |= self.edges[v]

      self.nodes.remove(v)
      del self.edges[v]
      del self.redges[v]
      self.edges[u].remove(v)

      for v_next in self.redges:
        if v in self.redges[v_next]:
          self.redges[v_next].remove(v)
          self.redges[v_next].add(u)

      utag = self.getTag(u)
      vtag = self.getTag(v)
      str1 = utag[1]
      str2 = vtag[1]
      if str1 == None:
          str1 = ""
      if str2 == None:
          str2 = ""
      self.setTag(u, (0x100, str1 + str2))

      return True

  def addEdge(self, u, v):
    self.nodes.add(u)
    if u not in self.edges:
      self.edges[u] = set()
    if u not in self.redges:
      self.redges[u] = set()

    self.nodes.add(v)
    if v not in self.edges:
      self.edges[v] = set()
    if v not in self.redges:
      self.redges[v] = set()

    self.edges[u].add(v)
    self.redges[v].add(u)

  def pprint(self):
    for u in self.nodes:
      id = u
      tag = self.getTag(u)
      dsts = list(self.edges[u])
      srcs = list(self.redges[u])
      print '%s: %r %s %s' % (id, tag, dsts, srcs)
