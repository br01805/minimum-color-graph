import pytest
import logging
import synapse.exc as s_exc

from libs.config import set_root_dir, set_profile, find_config_dir
from helpers.http_errors import SynapseError
from src.libs.cortex_db import CortexDb, read_async

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestSynapseSplices():

    async def test_syn_nodes(self):
        logger = logging.getLogger(__name__)
        try:
            cortex_db = CortexDb(logger)
            async with cortex_db.connect_yield() as syndb:
                msgs = [
                    (('inet:fqdn', 'woot1.com'),
                     {'tags': {'int.aka.botquaker': (None, None),
                               'bhv.c2c': (None, None),
                              }
                      }),
                    (('inet:ipv4', '23.23.23.23'),
                     {'tags': {'int.aka.botquaker': (None, None),
                               'bhv.c2c': (None, None),
                               }
                      }),

                ]
                err = await syndb.addFeedData('syn.nodes', msgs)
                query1 = await read_async(logger, syndb, 'inet:fqdn="woot1.com"')
                logger.debug(query1)
                assert len(query1) == 1
                query2 = await read_async(logger, syndb, '#int.aka')
                assert len(query2) == 2
                values = list(map(lambda x: x[1][0][1] if x[0] == 'node' else None, query2))
                logger.debug(query2)
                assert values == ['woot1.com', 387389207]

        except s_exc.SynErr as syn_err:
            print(syn_err)

    async def test_splice_error(self):
        logger = logging.getLogger(__name__)
        try:
            cortex_db = CortexDb(logger)
            async with cortex_db.connect_yield() as syndb:
                msgs = [
                    (('inet:fqdn2', 'woot1.com'),
                     {'tags': {'int.aka.botquaker': (None, None),
                               'bhv.c2c': (None, None),
                              }
                      }),
                    (('inet:ipv4', '23.23.23.256'),
                     {'tags': {'int.aka.botquaker': (None, None),
                               'bhv.c2c': (None, None),
                               }
                      }),

                ]
                err = await syndb.addFeedData('syn.nodes', msgs)
                query1 = await read_async(logger, syndb, 'inet:fqdn="woot1.com"')
                logger.debug(query1)
                assert len(query1) == 0
                query2 = await read_async(logger, syndb, '#int.aka')
                assert len(query2) == 0

        except s_exc.SynErr as syn_err:
            print(syn_err)
