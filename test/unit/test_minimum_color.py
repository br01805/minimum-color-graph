import logging
import pytest
from src.algorithms.backtracking import Backtracking
from src.algorithms.greedy import Greedy
from src.libs.config import set_root_dir, set_profile, find_config_dir

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestMinimumColoring:
    def test_backtracking(self):
        g = Backtracking(4)
        g.graph = [[0, 1, 2, 1], [1, 0, 1, 0], [1, 1, 0, 1], [1, 0, 1, 0]]
        color_max = 4
        result = g.graph_backtrack(color_max)
        assert result

    def test_backtracking_min_3(self):
        g = Backtracking(4)
        g.graph = [[0, 1, 2, 1], [1, 0, 1, 0], [1, 1, 0, 1], [1, 0, 1, 0]]
        color_max = 3
        result = g.graph_backtrack(color_max)
        assert result

    def test_backtracking_min_2(self):
        g = Backtracking(4)
        g.graph = [[0, 1, 2, 1], [1, 0, 1, 0], [1, 1, 0, 1], [1, 0, 1, 0]]
        color_max = 2
        result = g.graph_backtrack(color_max)
        assert not result

    def test_greedy(self):
        logger = logging.getLogger(__name__)
        greedy = Greedy(logger)
        g1 = [[] for i in range(4)]
        g1 = greedy.add_edge(g1, 0, 1)
        g1 = greedy.add_edge(g1, 0, 2)
        g1 = greedy.add_edge(g1, 1, 2)
        g1 = greedy.add_edge(g1, 1, 3)
        g1 = greedy.add_edge(g1, 2, 3)
        result = greedy.greedy_coloring(g1, 4)
        assert result

    def test_greedy_min_3(self):
        logger = logging.getLogger(__name__)
        greedy = Greedy(logger)
        g1 = [[] for i in range(4)]
        g1 = greedy.add_edge(g1, 0, 1)
        g1 = greedy.add_edge(g1, 0, 2)
        g1 = greedy.add_edge(g1, 1, 2)
        g1 = greedy.add_edge(g1, 1, 3)
        g1 = greedy.add_edge(g1, 2, 3)
        result = greedy.greedy_coloring(g1, 4)
        assert result