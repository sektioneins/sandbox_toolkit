#
# sb2dot - a sandbox binary profile to dot convertor for iOS 9 and OS X 10.11
# Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>
#    uses and extends code from Dionysus Blazakis with his permission
#
# module: outputdot.py
# task: cheap .dot file generator 
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

import os

def dump_node_to_dot(g, u, visited):

    if visited.has_key(u):
        return ""
    tag = g.getTag(u)
    tag = str(tag)
    tag = tag.replace("\\", "\\\\")
    tag = tag.replace("\"", "\\\"")
    tag = tag.replace("\0", "")
    edges = list(g.edges[u])
    
    visited[u] = True;
    out = "n%u [label=\"%s\"];\n" % (u, tag)
    
    if len(edges) == 0:
        return out
    
    out+= "n%u -> n%u [color=\"green\"];\n" % (u, edges[0]);
    out+= "n%u -> n%u [color=\"red\"];\n" % (u, edges[1]);
    
    out+=dump_node_to_dot(g, edges[0], visited)
    out+=dump_node_to_dot(g, edges[1], visited)
    
    return out;

def dump_to_dot(g, offset, name, cleanname, profile_name):
    u = offset * 8
    visited = {}
    
    orig_name = name
    
    if len(name) > 128:
        name = name[0:128]
    name = name + ".dot"
    name = name.replace("*", "")
    name = name.replace(" ", "_")
    
    cleanname = cleanname.replace("\\", "\\\\")
    cleanname = cleanname.replace("\"", "\\\"")
    cleanname = cleanname.replace("\0", "")
    
    profile_name = os.path.basename(profile_name)
    profile_name = profile_name.replace("\\", "\\\\")
    profile_name = profile_name.replace("\"", "\\\"")
    profile_name = profile_name.replace("\0", "")
    
    
    f = open(profile_name + "_" + name, 'w')
    print "[+]    generating " + profile_name + "_" + name
    
    f.write("digraph sandbox_decision { rankdir=HR; labelloc=\"t\";label=\"sandbox decision graph for\n\n%s\n\nextracted from %s\n\n\n\"; \n" % (cleanname, profile_name))
    out = "n0 [label=\"%s\";shape=\"doubleoctagon\"];\n" % (cleanname)
    out+= "n0 -> n%u [color=\"black\"];\n" % (u);
    out = out + dump_node_to_dot(g, u, visited)
    f.write(out)
    f.write("} \n")
    
    f.close()
