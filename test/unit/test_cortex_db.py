import logging
import pytest
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestCortexDb:
    @pytest.mark.asyncio
    async def test_cortex_recursive_global(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        await cortex_db.set_global(True)

        try:
            async with cortex_db:
                add_result = await read_async(None, cortex_db.conn(), '[inet:ipv4=52.52.52.52]')
                assert len(add_result) == 2
                assert add_result[0][0] == 'node:edits'
                get_result = await read_async(None, cortex_db.conn(), 'inet:ipv4=52.52.52.52')
                assert len(get_result) == 1
                assert get_result[0][1][0] == ('inet:ipv4', 875836468)

            async with cortex_db:
                get_result = await read_async(None, cortex_db.conn(), 'inet:ipv4=52.52.52.52')
                assert len(get_result) == 1
                assert get_result[0][1][0] == ('inet:ipv4', 875836468)

        finally:
            await cortex_db.set_global(False)

    @pytest.mark.asyncio
    async def test_cortex_yield_global(self):
        cortex_db = CortexDb(logging.getLogger(__name__))
        await cortex_db.set_global(True)

        try:
            async with cortex_db.connect_yield() as syncore:
                add_result = await read_async(None, syncore, '[inet:ipv4=52.52.52.52]')
                assert len(add_result) == 2
                assert add_result[0][0] == 'node:edits'
                get_result = await read_async(None, syncore, 'inet:ipv4=52.52.52.52')
                assert len(get_result) == 1
                assert get_result[0][1][0] == ('inet:ipv4', 875836468)

            async with cortex_db.connect_yield() as syncore:
                get_result = await read_async(None, syncore, 'inet:ipv4=52.52.52.52')
                assert len(get_result) == 1
                assert get_result[0][1][0] == ('inet:ipv4', 875836468)

        finally:
            await cortex_db.set_global(False)

    @pytest.mark.asyncio
    async def test_cortex_recursive_no_cache(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        await cortex_db.set_global(False)

        async with cortex_db:
            add_result = await read_async(None, cortex_db.conn(), '[inet:ipv4=52.52.52.52]')
            assert len(add_result) == 2
            assert add_result[0][0] == 'node:edits'
            async with cortex_db:
                get_result = await read_async(None, cortex_db.conn(), 'inet:ipv4=52.52.52.52')
                assert len(get_result) == 1
                assert get_result[0][1][0] == ('inet:ipv4', 875836468)

        async with cortex_db:
            get_result = await read_async(None, cortex_db.conn(), 'inet:ipv4=52.52.52.52')
            assert not get_result

    @pytest.mark.asyncio
    async def test_cortex_yield_no_cache(self):
        cortex_db = CortexDb(logging.getLogger(__name__))
        await cortex_db.set_global(False)

        async with cortex_db.connect_yield() as syncore:
            add_result = await read_async(None, syncore, '[inet:ipv4=52.52.52.52]')
            assert len(add_result) == 2
            assert add_result[0][0] == 'node:edits'
            get_result = await read_async(None, syncore, 'inet:ipv4=52.52.52.52')
            assert len(get_result) == 1
            assert get_result[0][1][0] == ('inet:ipv4', 875836468)

        async with cortex_db.connect_yield() as syncore:
            get_result = await read_async(None, syncore, 'inet:ipv4=52.52.52.52')
            assert not get_result