import pytest
from helpers.tag_utils import build_tag_tree_children


class TestBuildTagsTree():
    def test_normal(self):
        tag_list = [
            ('int', (1514772000000, 1514772000000)),
            ('int.tlp', (1514772000000, 1514772000000)),
            ('int.capsource', (1514772000000, 1514772000000)),
            ('int.capsource.ibm', (1514772000000, 1514772000000)),
            ('int.capsource.ibm.slack', (1514772000000, 1514772000000)),
            ('thr', (1514772000000, 1514772000000)),
            ('thr.test1', (1514772000000, 1514772000000)),
            ('int.tlp.white', (1514772000000, 1514772000000)),
            ('code', (1514772000000, 1514772000000)),
            ('code.level1', (1514772000000, 1514772000000)),
            ('code.level1.tag2', (1514772000000, 1514772000000)),
            ('code.level1.tag', (1514772000000, 1514772000000)),
            ('int.capsource.ibm.slack.ask_iris', (1514772000000, 1514772000000)),
        ]

        tag_list = sorted(tag_list, key=lambda tag: tag[0])
        tag_dict, tree_dict = build_tag_tree_children(tag_list)

        assert tag_dict
        assert isinstance(tag_dict, dict)
        assert len(tag_dict) == 5

        assert tree_dict
        assert isinstance(tree_dict, dict)
        assert len(tree_dict) == 8
        for tag, _ in tag_dict.items():
            assert tag not in tree_dict
        assert tree_dict['#int.tlp'] == ('2018-01-01T02:00:00Z', '2018-01-01T02:00:00Z')
        assert tree_dict['#code.level1'] == ('2018-01-01T02:00:00Z', '2018-01-01T02:00:00Z')
