import pytest
import sys
import os.path
from libs.config import get_config, set_root_dir, set_profile, get_dir


def find_config_dir():
    dir = os.path.join('..', '..', 'config')
    if (os.path.exists(dir)):
        return dir
    dir = os.path.join('..', 'config')
    if (os.path.exists(dir)):
        return dir
    dir = os.path.join('.', 'config')
    if (os.path.exists(dir)):
        return dir
    return ''


class TestConfig():

    def test_setup(self):
        dir = find_config_dir()
        set_root_dir(dir)
        assert(get_config)
        assert(get_dir())
        assert(get_config('logdir'))
        set_profile('development')
        assert(get_config('logdir'))

