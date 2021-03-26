import pytest
import logging
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.synapse_models.metrics import SynapseMetrics

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestSynapseMetrics:

    @pytest.mark.asyncio
    async def test_get_metrics_good(self):
        metrics = SynapseMetrics(logging.getLogger(__name__),
                                 add_nodes=(('inet:ipv4', '84.84.84.84'),
                                            ('inet:url', 'http://www.example.com/index.html'),
                                            ('inet:email', 'bill@example.com'),
                                            ('hash:md5', '900150983cd24fb0d6963f7d28e17f72'),
                                            ('syn:tag', 'thr.rednote'),
                                            ('syn:tag', 'code.blackpos')
                                            ))
        result = await metrics.run()
        assert result
        assert {'msg', 'data', 'status'} <= result.keys()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert result['data']['synapse']['value']['formcounts'] == {'inet:ipv4': 1, 'inet:url': 1,
                                                                    'inet:fqdn': 3, 'inet:email': 1, 'inet:user': 1,
                                                                    'hash:md5': 1, 'syn:tag': 4}
