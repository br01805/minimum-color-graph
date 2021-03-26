from pconf import Pconf
from typing import Tuple
import os
import logging
from os import path

class ConfigLoadError(Exception):
    pass

class ConfigValueMissing(Exception):
    pass

class ConfigManager():
    """This class manages the load and retrieval of configuration data for server. This class manages the load
      and retrieval of configuration data for server. This class reuses the pconf hierarchical configuration
      package. All the configuration data is loaded from JSON files in the 'conf' directory."""
    def __init__(self, root_dir='', profile=''):
        self.root_dir = root_dir
        self.profile = profile
        self.is_init = False
        self.pconf_obj = None

    def _init(self, logger):
        """Read the configuration data from files and profile"""
        if not self.is_init:
            if self.pconf_obj:
                self.pconf_obj.clear()
                Pconf.clear()
            Pconf.env()
            dir = self.get_dir()
            env_name = self.profile if (len(self.profile)) else os.getenv('PY_ENV', 'production')
            logger.debug('Configuration dir %s with env %s', dir, env_name)
            if path.isdir(dir):
                env_file = ''
                if env_name == 'production':
                    env_file = '%s/production_config.json' % dir
                elif env_name == 'development':
                    env_file = '%s/development_conf.json' % dir
                elif env_name == 'integration':
                    env_file = '%s/integration_config.json' % dir
                elif env_name == 'test':
                    env_file = '%s/test_config.json' % dir
                elif env_name == 'test_e2e':
                    env_file = '%s/test_e2e_config.json' % dir
                else:
                    raise ConfigLoadError('Unknown configuration profile: %s' % env_name)
                if not os.path.exists(env_file):
                    raise ConfigLoadError('Missing configuration file: %s' % env_file)
                Pconf.file(env_file, encoding='json')
                base_cfg_file = '%s/config.json' % dir
                if not os.path.exists(base_cfg_file):
                    raise ConfigLoadError('Missing configuration file: %s' % base_cfg_file)
                Pconf.file('%s/config.json' % dir, encoding='json')
            else:
                raise ConfigLoadError('Missing directory: %s' % dir)
            self.is_init = True
            self.pconf_obj = Pconf.get()

    def get_dir(self):
        """Get the configuration directory name"""
        dir = self.root_dir if len(self.root_dir) else os.path.join(os.getcwd(), 'config')
        if not os.path.isabs(dir):
            dir = os.path.join(os.getcwd(), dir)
        return dir

    def set_profile(self, name):
        """Set the configuration profile name"""
        self.profile = name
        self.is_init = False

    def set_root_dir(self, dir):
        """Set the configuration directory"""
        self.root_dir = dir
        self.is_init = False

    def get(self, name, enforce_none_check=True):
        """Get a configuration value"""
        logger = logging.getLogger(__name__)

        self._init(logger)
        assert self.pconf_obj
        if name not in self.pconf_obj:
            if enforce_none_check:
                raise ConfigValueMissing(name)
            return None
        return self.pconf_obj[name]

    def set(self, name: str, value) -> Tuple[str, any]:
        """Set (explicitly) a configuration name
        Args:
            name: configuration name string
            value: the configuration value
        Returns: the current configuration value that can potentially be used to restore the value

        """
        old_value = self.pconf_obj[name]
        self.pconf_obj[name] = value
        return (name, old_value)

the_config = ConfigManager()

def get_config(name, enforce_none_check=True):
    return the_config.get(name, enforce_none_check)

def check_config(names: list):
    """Check configuration value is not empty or set to all 'x'"""
    missing_values = []
    for name in names:
        val = get_config(name, False)
        if not val:
            missing_values.append(name)
            continue
        repeat_count = 0
        for c in val:
            if c != 'x':
                break
            repeat_count += 1
        if repeat_count == len(val):
            missing_values.append(name)

    if missing_values:
        raise ConfigValueMissing(missing_values)

def set_root_dir(dir):
    return the_config.set_root_dir(dir)

def get_dir():
    return the_config.get_dir()

def set_profile(name):
    return the_config.set_profile(name)

def find_config_dir():
    dir = os.path.join('..', '..', 'config')
    if os.path.exists(dir):
        return dir
    dir = os.path.join('..', 'config')
    if os.path.exists(dir):
        return dir
    dir = os.path.join('.', 'config')
    if os.path.exists(dir):
        return dir
    return ''
