import json
import logging
import os
import pytest

from tornado import httputil
from tornado.testing import AsyncHTTPTestCase, gen_test
import tornado
import server
from libs.config import set_profile, set_root_dir, find_config_dir, get_config
from libs.dev_env import DevEnv
from libs.cortex_db import CortexDb


# To Run these tests, you must set the cortex_password and CORTEX_SERVICE_ENABLED environment variables
@pytest.mark.skipif('CORTEX_SERVICE_ENABLED' not in os.environ, reason='requires a Synapse database connection')
class TestEvilRoutes(AsyncHTTPTestCase):
    """Storm test cases."""

    h = httputil.HTTPHeaders({
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

    @gen_test(timeout=200)
    def test_get_evil(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_cursor(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/cursor/1473364427000'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_ip(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/ip'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_ip_cursor(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/ip/cursor/1473364427000'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_domain(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/domain'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_domain_cursor(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/domain/cursor/1473364427000'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_hash(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/hash'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_hash_cursor(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil/hash/cursor/1473364427000'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_limit(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil?limit=3'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'

    @gen_test(timeout=200)
    def test_get_evil_private(self):
        """Test metric endpoint"""
        response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/evil?private=True'),
                                                method='GET',
                                                headers=TestEvilRoutes.h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
