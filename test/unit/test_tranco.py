import pytest
import logging
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.tranco import TrancoRanked

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestTranco:
    @pytest.mark.asyncio
    async def test_get_tranco_list(self):
        logger = logging.getLogger(__name__)
        t_class = TrancoRanked(logger)
        result = t_class.get_list().list
        assert 'google.com' in result

    @pytest.mark.asyncio
    async def test_get_tranco_ranked(self):
        logger = logging.getLogger(__name__)
        t_class = TrancoRanked(logger)
        result = t_class.is_ranked('google.com')
        assert result

    @pytest.mark.asyncio
    async def test_get_tranco_not_ranked(self):
        logger = logging.getLogger(__name__)
        t_class = TrancoRanked(logger)
        result = t_class.is_ranked('brianrawls.com')
        assert not result
