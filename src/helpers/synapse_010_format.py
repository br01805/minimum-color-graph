"""This module contains a set of Synapse 010 "accessor" functions that access specific traits from Storm queries."""
from typing import Optional, Any

def sf_get_guid(data) -> Optional[str]:
    """Get the Synapse 010 GUID from a node"""
    result = None
    if data:
        assert isinstance(data, tuple)
        assert len(data) == 2
        assert data[0] == 'node'
        result = data[1][1]['iden']
    return result

def sf_was_added(query_results, primary_node) -> bool:
    """Check if query results indicate a new node was added

    Args:
        query_results: a list of Synapse nodes; the code is looking for the first 'node'
        primary_node: the node returned from sf_get_first_node()

    Returns: True if query resulted in new node being added; otherwise False
    """
    for node in query_results:
        if node[0] == 'node:edits' and node[1]['edits'][0][1] == primary_node[1][0][0]:
            return True
    return False

def sf_get_first_node(query_results: list) -> Optional[tuple]:
    """Get the first node from a Synapse ask() response

    Args:
        query_results: a list of Synapse nodes; the code is looking for the first 'node'

    Returns: The first node in the list or None if 'node' is found
    """
    assert isinstance(query_results, list)
    result = None
    found_node = list(filter(lambda x: x[0] == 'node', query_results))
    if found_node:
        result = found_node[0]
    return result

def sf_has_property(field: str, data: tuple) -> bool:
    """Check if a Synpase node has secondary property

    Args:
        field: The field name to check if present
        data: The Synapse node to check

    Returns: True if 'field' property is present; otherwise False
    """
    assert isinstance(data, tuple)
    assert isinstance(data[1], tuple)
    assert isinstance(data[1][0], tuple)
    assert isinstance(data[1][1], dict)
    return field in data[1][1]['props']


def sf_get_property_value(field: str, data: tuple) -> Any:
    """Get the value from the secondary properties

    Args:
        field: The field name to check if present
        data: The Synapse node to check

    Returns: The property value if present; otherwise None
    """
    assert isinstance(data, tuple)
    assert isinstance(data[1], tuple)
    assert isinstance(data[1][0], tuple)
    assert isinstance(data[1][1], dict)
    return data[1][1]['props'].get(field)

def sf_get_form_name(data: tuple) -> str:
    """Get the form name (inet:ipv4) from a Synapse node

    Args:
        data: The Synapse node to check

    Returns: The synapse node's name string
    """
    result = None
    if data:
        assert isinstance(data, tuple)
        assert isinstance(data[1], tuple)
        assert isinstance(data[1][0], tuple)
        assert isinstance(data[1][1], dict)
        result = data[1][0][0]
    return result

def sf_get_form_value(data: tuple) -> str:
    """Get the form value (23.23.23.23) from a Synapse node

    Args:
        data: The Synapse node to check

    Returns: The synapse node's value string
    """
    result = None
    if data:
        assert isinstance(data, tuple)
        assert isinstance(data[1], tuple)
        assert isinstance(data[1][0], tuple)
        assert isinstance(data[1][1], dict)
        result = data[1][0][1]
    return result


def sf_find_max_timestamp(data: tuple, upper_limit: int):
    """Get the maximum timestamp given a list of Synapse query nodes"""
    cursor = ''
    is_limit_reached = False
    for ioc in data:
        if ioc[0] == 'print':
            mesg = ioc[1].get('mesg')
            if mesg and mesg.startswith('limit reached'):
                is_limit_reached = True
                break

    if is_limit_reached:
        cursor = 0
        for ioc in data:
            if ioc[0] == 'node':
                if ioc[1][1]['props']['.created'] > cursor:
                    cursor = ioc[1][1]['props']['.created']
    return cursor
