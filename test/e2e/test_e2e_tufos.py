import json
import logging
import os
import pytest

from tornado import escape
from tornado.testing import AsyncHTTPTestCase, gen_test
import tornado
import server
from libs.config import set_profile, set_root_dir, find_config_dir, get_config
from libs.dev_env import DevEnv
from libs.cortex_db import CortexDb


# To Run these tests, you must set the cortex_password and CORTEX_SERVICE_ENABLED environment variables
# CORTEX_SERVICE_ENABLED=1;cortex_password=<pass>
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
    def test_all(self):
        post_body = {
            'name': 'inet:ipv4=23.23.23.24',
            'tags': ['int.capsource.vt']
        }

        while True:
            try:
                json_body = escape.json_encode(post_body)
                response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos'),
                                                        method='POST',
                                                        headers=TestTufosRoute.h,
                                                        body=json_body)
                result = json.loads(response.body)
                break
            except tornado.httpclient.HTTPError as e:
                print(e)
                ##### DELETE the existing node and retry sequence again
                if e.code == 409:
                    response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos/inet:ipv4=23.23.23.24'),
                                                            method='GET',
                                                            headers=TestTufosRoute.h)
                    result = json.loads(response.body)
                    assert result

                    guid = result['data']['guid']
                    response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos/%s' % guid),
                                                            method='DELETE',
                                                            headers=TestTufosRoute.h)
                    result = json.loads(response.body)
                    assert result['data']['guid'] == guid

        ##### GET request
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos/inet:ipv4=23.23.23.24'),
                                                method='GET',
                                                headers=TestTufosRoute.h)
        result = json.loads(response.body)
        assert result
        assert result['msg'] == 'success'
        guid = result['data']['guid']

        ###### PUT request
        put_body = {
            'type': 'internal',
            'asn': 1000
        }
        json_body = escape.json_encode(put_body)
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos/inet:ipv4=23.23.23.24'),
                                                method='PUT',
                                                headers=TestTufosRoute.h,
                                                body=json_body)
        result = json.loads(response.body)
        assert result
        assert result['msg'] == 'success'

        ###### DELETE request
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos/%s' % guid),
                                                method='DELETE',
                                                headers=TestTufosRoute.h)
        result = json.loads(response.body)
        assert response.code == 200
        guid = result['data']['guid']
        assert result['msg'] == 'success'

        try:
            yield self.http_client.fetch(self.get_url('/src/v1/synapse/tufos/%s' % guid),
                                         method='DELETE',
                                         headers=TestTufosRoute.h)
            result = json.loads(response.body)
        except tornado.httpclient.HTTPError as e:
            assert(e.message == 'Gone')
            result = json.loads(e.response.body)
            assert result
            assert result['msg'] == 'missing_resource'
