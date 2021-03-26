import pytest

from helpers.status import status
from helpers.dict_utils import clean_dict
from helpers.gen_response import (gen_return, report_publish_return, restful_return, mss_return,
                                  tag_return)
from libs.find_tags import find_tags

@pytest.mark.skip('00xx test')
class TestGenerateResponse:
    """Test Storm Methods."""

    def test_gen_response(self):
        """Test response json helpers."""
        genreturntest = gen_return()
        publishreturntest = report_publish_return()
        # TODO Update code to use correct API return
        # restfulreturntest = restful_return()
        mssreturntest = mss_return()
        tagreturntest = tag_return()

        assert genreturntest == {
            'msg': 'success',
            'data': None,
            'status': 0,
        }

        assert publishreturntest == {
            'type': "report",
            'content-type': "undefined",
            'seen': "",
            'title': "",
            'author': "",
            'org': "",
            'summary': "",
            'publish': False,
            'tlp': "",
            'indicators': {},
            'tags': {},
            'report': 'N/A'

        }

        assert restfulreturntest == {
            "guid": "",
            "type": "",
            "property": "",
            "secondary_property": {},
            "tags": {},
            "tag_tree": {},
            "category": "",
        }

        assert mssreturntest == {
            "type": "",
            "seen": "",
            "tags": {},
            "properties": {}
        }

        assert mssdatatest == {
            "indicators": {},
            "nextcursor": ""
        }

        assert tagreturntest == {
            "guid": "",
            "tag": "",
            "doc": "",
            "title": ""
        }

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

    def test_restful_formats_ipv4(self):
        """Test restful formats"""
        restfulipv4 = [
            [
                '1b60796dc25c527170718ea858114f6b',
                {
                    '#int': 1543812315131,
                    '#int.tlp': 1543812315131,
                    'inet:ipv4': '8.8.8.8',
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

    def test_bulk_query_format_ipv4(self):
        bulkqueryipv4 = [
            [
                '1b60796dc25c527170718ea858114f6b',
                {
                    '#int': 1543812315131,
                    '#int.tlp': 1543812315131,
                    'inet:ipv4': '8.8.8.8',
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
        bulkquerydata = bulkquery_format(bulkqueryipv4)
        assert bulkquerydata == [
            {
                'guid': '1b60796dc25c527170718ea858114f6b',
                'type': 'inet:ipv4',
                'property': '8.8.8.8',
                'secondary_property': {
                    'inet:ipv4': '8.8.8.8',
                    'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                    'tufo:form': 'inet:ipv4',
                    'inet:ipv4:cc': 'us',
                    'node:created': '11-23-2018T',
                    'inet:ipv4:asn': 15169,
                    'inet:ipv4:type': '??'
                },
                'tags': {
                    '#int.tlp.white': 1543812315131
                },
                'tag_tree': {
                    '#int': '12-03-2018T',
                    '#int.tlp': '12-03-2018T',
                    '#int.tlp.white': '12-03-2018T'
                },
                'category': 'none'
            }
        ]
