import pytest
import json
import logging
import os

from tornado import httpclient, escape
from tornado.testing import AsyncHTTPTestCase, gen_test
import tornado
import server
from libs.config import set_profile, set_root_dir, find_config_dir, get_config
from libs.dev_env import DevEnv
from libs.cortex_db import CortexDb

# To Run these tests, you must set the cortex_password and CORTEX_SERVICE_ENABLED environment variables
@pytest.mark.skipif('CORTEX_SERVICE_ENABLED' not in os.environ, reason='requires a Synapse database connection')
class TestBulkImportRoute(AsyncHTTPTestCase):
     """Bulk import test cases."""

     def get_app(self):
         """Create new Tornado test server application"""
         dir_name = find_config_dir()
         set_root_dir(dir_name)
         set_profile('test_e2e')
         if get_config('add_test_data'):
             DevEnv(CortexDb(logging.getLogger('synapse'), True)).add()
         return server.make_app2()

     @gen_test(timeout=200)
     def test_good_request(self):
         """Test sending valid bulk import."""
         post_args = {}
         post_args['nodes'] = {
             'line1': {
                 'iocs': {
                     'comment': 'Specifies an IoC indicator string for the key. The value is the Synapse data model tufo string.',
                     'hash1': 'hash:sha1',
                     'hash2': 'hash:md5',
                 },
                 'tags': ['tag1', 'tag2']
             },
             'line2': {
                 'iocs': {
                     'hash3': 'hash:sha1',
                     'hash4': 'hash:md5',
                 },
                 'tags': ['tag1', 'tag2']
             }
         }
         json_body = escape.json_encode(post_args)
         h = tornado.httputil.HTTPHeaders({
             'content-type': 'application/json',
             'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
             'X-User': '{"userId": 1000, "email": "george@example.com"}'
         })

         response = yield self.http_client.fetch(self.get_url('/src/v1/synapse/bulk_import'),
                                                 method='POST',
                                                 body=json_body,
                                                 headers=h)
         result = json.loads(response.body)
         assert response.code == 200
         assert result['msg'] == "success"
