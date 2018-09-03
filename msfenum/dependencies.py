# -*- coding: utf-8 -*-

from collections import defaultdict

import logging
log = logging.getLogger(__name__)


class Graph(object):
    """ Docstring for Graph. """
    def __init__(self, vertices):
        self.graph = defaultdict(list)  # dictionary containing adjacency List
        self.V = vertices               # No. of vertices

    def add_edge(self, u, v):
        """ function to add an edge to graph """
        self.graph[u].append(v)

    def _sort(self, v, visited, stack):
        """ A recursive function used by topologicalSort """
        # Mark the current node as visited.
        visited[v] = True
        # Recur for all the vertices adjacent to this vertex
        for i in self.graph[v]:
            if not visited[i]:
                self._sort(i, visited, stack)
        # Push current vertex to stack which stores result
        stack.insert(0, v)

    def sort(self):
        """ The function to do Topological Sort """
        # Mark all the vertices as not visited
        visited = [False] * self.V
        stack = []
        # Call the recursive helper function to store Topological
        # Sort starting from all vertices one by one
        for i in range(self.V):
            if not visited[i]:
                self._sort(i, visited, stack)
        # Print contents of stack
        return stack
