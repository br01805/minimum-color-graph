import pytest
import logging
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.synapse_models.text_indicators import TextIndicators

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True


@pytest.mark.usefixtures("setup_config")
@pytest.mark.skip(reason='requires Scraper service to be online')
class TestTextIndicators:

    def test_scrape_indicators_good(self):
        text = '84.84.84.84 http://www.example.com/index.html bill@example.com'
        text_indicators = TextIndicators(logging.getLogger(__name__), text,
                                         adjacent_ref_names=None,
                                         adjacent_ref_count=0,
                                         add_nodes=(('inet:ipv4', '84.84.84.84'),
                                                     ('inet:url', 'http://www.example.com/index.html'),
                                                     ('inet:email', 'bill@example.com')))
        result = text_indicators.run()
        assert result
        assert {'status', 'msg', 'data'} <= result.keys()
        assert isinstance(result['data'], list)
        assert len(result['data']) == 3



