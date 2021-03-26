#!/usr/bin/env python
"""
gen_return.py
This file generates the return schema for all answers from the API.
This is a helper function as if we want to update the schema returned,
all that is required is this file be changed.
"""


def gen_return(msg='success', data=None, status=0):
    """# API SCHEMA v1."""
    return_obj = {
        'msg': msg,
        'data': data,
        'status': status,
    }
    return return_obj

def gen_return_cursor(msg='success', data=None, cursor='', status=0):
    return_obj = {
        'msg': msg,
        'data': data,
        'status': status,
        'cursor': cursor
    }
    return return_obj


def report_publish_return():
    """ Report Format For Feed """
    published_report = {'type': 'report',
                        'content-type': 'undefined',
                        'seen': '',
                        'title': '',
                        'author': '',
                        'org': '',
                        'summary': '',
                        'publish': False,
                        'tlp': '',
                        'indicators': {},
                        'tags': {},
                        'report': 'N/A'
                        }
    return published_report


def restful_return(guid: str,
                   type: str,
                   property: str,
                   created: int,
                   secondary_props: dict,
                   tagprops: dict = None,
                   pivot_path: dict = None):
    """Create a Sherlockv2 node format object that is foundation of API

    Args:
        guid (str): The node's globally unique identifier
        type (str): The Synapse tuple/model format type string (inet:ipv4)
        property: The type's value
        created: The current UTC timestamp that entry is added to database (firstSeen)
        secondary_props: A dictionary of node specific properties (inet:ipv4 :asn)

    Return:
        An object that should be associated with an API response
    """
    assert guid
    assert type
    assert created
    assert isinstance(secondary_props, dict)
    assert tagprops is None or isinstance(tagprops, dict)
    assert pivot_path is None or isinstance(pivot_path, dict)

    restful_publish = {
        'guid': guid,
        'type': type,
        'property': property,
        'created': created,
        'secondary_property': secondary_props,
        'tags': {},
        'tag_tree': {},
        'tagprops': tagprops if tagprops is None or len(tagprops.keys()) else None,
        'pivot_path': pivot_path if pivot_path is None or len(pivot_path.keys()) else None,
        'category': '',
    }
    return restful_publish


def mss_return(type: str, seen: int, secondary_props: dict):
    """Create a Sherlockv2 node format object that is foundation of API

    Args:
        type (str): The Synapse tuple/model format type string (inet:ipv4)
        seen: The current UTC timestamp that entry is added to database (firstSeen)

    Return:
        An object that should be associated with an API response
    """
    assert type
    assert seen
    assert secondary_props and isinstance(secondary_props, dict)

    restful_publish = {
        'type': type,
        'seen': seen,
        'tags': [],
        'properties': secondary_props
    }
    return restful_publish


def evil_return(type: str, first_seen: str, last_seen: str):
    """Create a Sherlockv2 node format object that is foundation of API

    Args:
        type (str): The Synapse tuple/model format type string (inet:ipv4)
        seen: The current UTC timestamp that entry is added to database (firstSeen)
        misc: Any additional data

    Return:
        An object that should be associated with an API response
    """
    assert type
    assert first_seen
    assert last_seen

    restful_publish = {
        'type': type,
        'firstSeen': first_seen,
        'lastSeen': last_seen,
        'misc': {},
        'tags': [],
    }
    return restful_publish


def mss_data():
    restful_publish = {
        'indicators': {},
        'nextcursor': ''
    }
    return restful_publish


def tag_data():
    tag_publish = {
        'title': '',
        'doc': ''
    }
    return tag_publish


def ioc_data():
    ioc_publish = {
        'type': '',
        'seen': '',
        'tags': {}
    }
    return ioc_publish


def tag_return():
    tag_publish = {
        'guid': '',
        'tag': '',
        'doc': '',
        'title': ''
    }
    return tag_publish


def reports_return():
    reports_publish = {
        'filename': 'N/A',
        'content-type': 'undefined',
        'threats': 0
    }
    return reports_publish


def bulkquery_return():
    restful_publish = {
        'guid': '',
        'type': '',
        'property': '',
        'secondary_property': {},
        'tags': {},
        'tag_tree': {},
        'category': ''
    }
    return restful_publish


def report_repositories():
    repos = ['#int.content.type.malware',
             '#int.content.type.industry',
             '#int.content.type.threatgroup']
    return repos
