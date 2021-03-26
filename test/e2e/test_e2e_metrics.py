import json
import os
import pytest

from tornado.testing import AsyncHTTPTestCase, gen_test
import tornado
import server
from libs.config import set_profile, set_root_dir, find_config_dir, get_config
#from libs.dev_env import DevEnv

# To Run these tests, you must set the cortex_password and CORTEX_SERVICE_ENABLED environment variables
@pytest.mark.skipif('CORTEX_SERVICE_ENABLED' not in os.environ, reason='requires a Synapse database connection')
class TestTufosRoute(AsyncHTTPTestCase):
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
        # if get_config('add_test_data'):
        #     devenv = DevEnv(CortexDb(logging.getLogger('synapse'), True))
        #     await devenv.add()
        return server.make_app2()

    @gen_test(timeout=200)
    def test_get_metrics(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/metrics'),
                                                method='GET',
                                                headers=TestTufosRoute.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
        assert 'synapse' in result['data'] and 'formcounts' in result['data']['synapse']
