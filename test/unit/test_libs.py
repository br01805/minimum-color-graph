import pytest
import sys

from helpers.status import status
from helpers.dict_utils import clean_dict, safeget
from libs.find_tags import find_tags

class TestStormMethods:
    """Test Storm Methods."""

    def test_status(self):
        """Test Status Converter."""
        success = status(0)
        notfound = status(1)

        assert success == 200
        assert notfound == 404

    def test_clean_dict(self):
        """Test clean dictionary."""
        clean = {"test": "success"}
        data = clean_dict(clean)

        assert data == {"test": "success"}

    def test_safeget_good(self):
        """Test safe get on dictionary."""
        obj1 = {
            'dict1': {
                'dict2': {
                    'value1': 'hello'
                }
            }
        }
        result = safeget(obj1, ('dict1', 'dict2', 'value1'))
        assert result == 'hello'

        result = safeget(obj1, ('dict1', 'dict2', 'bad'))
        assert result is None

        result = safeget(None, ('dict1', 'dict2'))
        assert result is None

    def test_find_tags(self):
        '''Test find all tags.'''
        findtag = [
            [
                '1b60796dc25c527170718ea858114f6b',
                {
                    '#int': 1543812315131,
                    '#int.tlp': 1543812315131,
                    'inet:ipv4': 134744072,
                    'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                    'tufo:form': 'inet:ipv4',
                    'inet:ipv4:cc': 'us',
                    'node:created': 1543006559273,
                    'inet:ipv4:asn': 15169,
                    '#int.tlp.white': 1543812315131,
                    'inet:ipv4:type': '??'
                }
            ]
        ]
        data = find_tags(findtag)

        assert data == [
            [
                '1b60796dc25c527170718ea858114f6b',
                {
                    'inet:ipv4': 134744072,
                    'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                    'tufo:form': 'inet:ipv4',
                    'inet:ipv4:cc': 'us',
                    'node:created': 1543006559273,
                    'inet:ipv4:asn': 15169,
                    'inet:ipv4:type': '??'
                }
            ]
        ]
