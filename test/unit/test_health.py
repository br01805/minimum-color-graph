import pytest
import logging
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.synapse_models.health import ServerHealth

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestSynapseMetrics:

    @pytest.mark.asyncio
    async def test_health_good(self):
        health = ServerHealth(logging.getLogger(__name__),
                              add_nodes=(('inet:ipv4', '84.84.84.84'),
                                         ('inet:url', 'http://www.example.com/index.html'),
                                         ('inet:email', 'bill@example.com'),
                                         ('hash:md5', '900150983cd24fb0d6963f7d28e17f72')))
        result = await health.run()
        assert result
        assert {'msg', 'data', 'status'} <= result.keys()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert result['data']['synapse'] == 'ok'
        assert result['data']['arango'] == 'ok'


