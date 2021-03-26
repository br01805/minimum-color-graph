import logging
import pytest
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb
from libs.synapse_models.cortex_users import CortexUser

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestCortexUser:
    @pytest.mark.asyncio
    async def test_add_reader(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        ctx_usr = CortexUser(logging.getLogger(__name__), cortex_db)
        result = await ctx_usr.add_user('reader', 'testpassword')
        assert result == ['root', 'reader']