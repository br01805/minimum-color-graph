"""File is a helper for unsupported characters."""
import ast
import json


def clean_dict(_dict):
    """Convert to suitable Json and indent."""
    return ast.literal_eval(json.dumps(_dict, sort_keys=True, indent=2))


def safeget(_dict: dict, keys, default=None):
    """Safely get a deep set of dictionary keys

    Args:
        _dict (dict): The input dictionary
        keys (list): A list of keys to find
        default: The default value to return if one or more keys are not found

    Returns: Object
    """
    assert keys and isinstance(keys, tuple)

    for key in keys:
        if isinstance(_dict, dict):
            _dict = _dict.get(key, default)
        else:
            return default
    return _dict
