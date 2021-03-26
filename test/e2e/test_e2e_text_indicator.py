import json
import logging
import pytest

from tornado.testing import AsyncHTTPTestCase, gen_test
import tornado
import server
from libs.config import set_profile, set_root_dir, find_config_dir, get_config
from libs.dev_env import DevEnv
from libs.cortex_db import CortexDb

@pytest.mark.skipif(True, reason="requires Synapse database and scraper connections")
class TestTextIndicatorsRoute(AsyncHTTPTestCase):
    """Test Tufos routing test cases."""

    h = tornado.httputil.HTTPHeaders({
        'content-type': 'application/json',
        'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
        'X-User': '{"userId": 1000, "email": "george@example.com"}'
    })

    def get_app(self):
        """Create new Tornado test server application"""
        dir_name = find_config_dir()
        set_root_dir(dir_name)
        set_profile('test_e2e')
        if get_config('add_test_data'):
            DevEnv(CortexDb(logging.getLogger('synapse'), True)).add()
        return server.make_app2()

    def test_get_text_indicator(self):
        """Test metric endpoint"""
        response = self.fetch('/src/v1/synapse/text_indicators/google.com%209.9.9.9',
                              method='GET',
                              headers=TestTextIndicatorsRoute.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
        assert 'data' in result
        assert isinstance(result['data'], list)
        assert len(result['data']) == 2

