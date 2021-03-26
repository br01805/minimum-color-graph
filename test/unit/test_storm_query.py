import pytest
import logging
from helpers.http_errors import SynapseError
from libs.config import get_config, set_root_dir, set_profile, find_config_dir
from libs.synapse_models.storm_query import StormQuery
from libs.userctx import UserContext

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestStormQuery():
    @pytest.mark.asyncio
    async def test_good_storm(self):
        userctx = UserContext.create_test('bill@example.com', 0, '111111')
        test_nodes = [('inet:ipv4', '2.2.2.2'),
                      ('inet:fqdn', 'www.malware.biz'),
                      ('inet:dns:a', ('www.malware.biz', '2.2.2.2')),
                      ]
        storm_query = StormQuery(logging.getLogger(__name__), 'inet:dns:a -> *', userctx, test_nodes)
        results = await storm_query.run()
        assert {'status', 'msg', 'data'} <= results.keys()
        assert len(results['data']) == 2
        props = ('www.malware.biz', '2.2.2.2')
        props_index = 0
        for node in results['data']:
            assert node['property'] == props[props_index]
            props_index += 1

    @pytest.mark.asyncio
    async def test_good_storm_limit(self):
        userctx = UserContext.create_test('bill@example.com', 0, '111111')
        test_nodes = [('inet:ipv4', '1.1.1.1'),
                      ('inet:ipv4', '2.2.2.2'),
                      ('inet:ipv4', '3.3.3.3'),
                      ]
        storm_query = StormQuery(logging.getLogger(__name__), 'inet:ipv4 | limit 2', userctx, test_nodes)
        results = await storm_query.run()

        assert {'status', 'msg', 'data'} <= results.keys()
        assert len(results['data']) == 2
        props = ('1.1.1.1', '2.2.2.2')
        props_index = 0
        for node in results['data']:
            assert node['property'] == props[props_index]
            props_index += 1

    @pytest.mark.asyncio
    async def test_bad(self):
        userctx = UserContext.create_test('bill@example.com', 0, '111111')
        with pytest.raises(SynapseError) as excinfo:
            storm_query = StormQuery(logging.getLogger(__name__), 'inet:ipv5', userctx)
            await storm_query.run()

