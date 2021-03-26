#!/usr/bin/python3
import logging
import os

from version import __version__
from libs.config import get_config
from algorithms.greedy import Greedy
from algorithms.backtracking import Backtracking
from libs.logging import setup_logging

setup_logging()
logger = logging.getLogger('synapse')
profile = os.getenv('PY_ENV', 'development')
logger.info('Minimum Color Graph: %s (%s)', __version__, profile)

# Greedy Algorithm
print("------ Greedy Algorithm --------- ")
greedy = Greedy(logger)
g1 = [[] for i in range(5)]
g1 = greedy.addEdge(g1, 0, 1)
g1 = greedy.addEdge(g1, 0, 2)
g1 = greedy.addEdge(g1, 1, 2)
g1 = greedy.addEdge(g1, 1, 3)
g1 = greedy.addEdge(g1, 2, 3)
g1 = greedy.addEdge(g1, 3, 4)
print("Coloring of graph 1 ")
greedy.greedyColoring(g1, 5)

g2 = [[] for i in range(5)]
g2 = greedy.addEdge(g2, 0, 1)
g2 = greedy.addEdge(g2, 0, 2)
g2 = greedy.addEdge(g2, 1, 2)
g2 = greedy.addEdge(g2, 1, 4)
g2 = greedy.addEdge(g2, 2, 4)
g2 = greedy.addEdge(g2, 4, 3)
print("\nColoring of graph 2")
greedy.greedyColoring(g2, 5)

# Backtracking Algorithm
print("------ Backtracking Algorithm --------- ")
g = Backtracking(4)
g.graph = [[0, 1, 1, 1], [1, 0, 1, 0], [1, 1, 0, 1], [1, 0, 1, 0]]
m = 3
g.graphColouring(m)