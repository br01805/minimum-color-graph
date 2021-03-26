import pytest
import json
import logging
from libs.config import get_config, set_root_dir, set_profile, find_config_dir
import helpers.scrape_indicators as si
import helpers.http_errors as errors

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True


class MyHttpResponse:
    def __init__(self):
        resp = {
            'status': 'success',
            'data': (
                {'type': 'inet:ipv4', 'property': '84.84.84.84'},
                {'type': 'inet:fqdn', 'property': 'www.example.com'},
            ),
            'code': 0,
        }
        json_str = json.dumps(resp)

        self.body = json_str

class MyHttpClient:
    def fetch(self, url, headers=None):
        return MyHttpResponse()

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestScrapeIndicators:

    @pytest.mark.skip(reason="requires Scraper service to be online")
    def test_connected_scrape(self):
        text = '84.84.84.84 www.example.com'
        user_headers = {
            'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
            'X-User': '{"userId": 1000, "email": "george@example.com"}'
        }
        result = si.scrape_indicators(logging.getLogger(__name__), text, parent_req_headers=user_headers)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]['type'] == 'inet:fqdn'
        assert result[1]['type'] == 'inet:ipv4'

    @pytest.mark.skip(reason="requires Scraper service to be offline")
    def test_disconnected_scrape(self):
        text = '84.84.84.84 www.example.com'
        with pytest.raises(si.ScraperServiceError):
            si.scrape_indicators(logging.getLogger(__name__), text)

    async def test_mocked_scrape(self):
        text = '84.84.84.84 www.example.com'
        result = await si.scrape_indicators(logging.getLogger(__name__), text, http_client=MyHttpClient())
        assert len(result) == 2
        assert {'type', 'property'} <= result[0].keys()
        assert result[0]['type'] == 'inet:ipv4'
        assert result[0]['property'] == '84.84.84.84'

    async def test_scrape_missing_text(self):
        with pytest.raises(errors.ParameterError):
            await si.scrape_indicators(logging.getLogger(__name__), '')

    async def test_scrape_wrong_variable_type(self):
        with pytest.raises(errors.ParameterError):
            await si.scrape_indicators(logging.getLogger(__name__), -1)

        with pytest.raises(errors.ParameterError):
            await si.scrape_indicators(logging.getLogger(__name__), ['string'])