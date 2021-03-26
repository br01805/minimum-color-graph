"""
status.py
This file is a simple helper to generate HTTP codes
"""


def status(httpstatus):
    """Convert Code to HTTP Status."""
    if httpstatus == 0:
        return 200
    if httpstatus == 1:
        return 404


# def libstatus(iterator):
#     """Convert Code to HTTP Status."""
#     iterator = iter(iterator)
#     try:
#         first = next(iterator)
#     except StopIteration:
#         return 400
#     return 207
