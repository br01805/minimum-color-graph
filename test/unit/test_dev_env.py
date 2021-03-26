import pytest
import logging
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.dev_env import DevEnv
from libs.cortex_db import CortexDb

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
@pytest.mark.skip('00xx test')
class TestDevEnv():
    def test_setup_db(self):
        cortex_db = CortexDb(logging.getLogger(__name__), is_recursive=True)
        with cortex_db:
            dev_env1 = DevEnv(cortex_db)
            dev_env1.add()

            dev_env2 = DevEnv(cortex_db)
            dev_env2.add()

