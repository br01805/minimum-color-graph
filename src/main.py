#!/usr/bin/python3
import logging
import os
import time

from version import __version__
from libs.config import get_config
from algorithms.greedy import Greedy
from algorithms.backtracking import Backtracking
from libs.logging import setup_logging

setup_logging()
logger = logging.getLogger('synapse')
profile = os.getenv('PY_ENV', 'development')
logger.info('Minimum Color Graph: %s (%s)', __version__, profile)


def run_greedy():
    """Greedy Algorithm"""
    print("------ Greedy Algorithm --------- ")
    start = time.perf_counter()
    greedy = Greedy(logger)
    g1 = [[] for i in range(4)]
    g1 = greedy.add_edge(g1, 0, 1)
    g1 = greedy.add_edge(g1, 0, 2)
    g1 = greedy.add_edge(g1, 1, 2)
    g1 = greedy.add_edge(g1, 1, 3)
    g1 = greedy.add_edge(g1, 2, 3)
    print("Coloring of graph 1 ")
    greedy.greedy_coloring(g1, 4)
    finish = time.perf_counter()
    seconds = (finish - start) * 1000
    print('Greedy algorithm took %s milliseconds' % seconds)

def run_backtracking():
    """Backtracking Algorithm"""
    print("\n------ Backtracking Algorithm --------- ")
    start = time.perf_counter()
    g = Backtracking(4)
    g.graph = [[0, 1, 2, 1], [1, 0, 1, 0], [1, 1, 0, 1], [1, 0, 1, 0]]
    m = 4
    g.graph_backtrack(m)
    finish = time.perf_counter()
    seconds = (finish - start) * 1000
    print('Backtracking took %s milliseconds' % seconds)


run_greedy()
run_backtracking()