import json
import logging
import os
import pytest

from tornado import httpclient, escape
from tornado.testing import AsyncHTTPTestCase, gen_test
import tornado
import server
from libs.config import set_profile, set_root_dir, find_config_dir, get_config
from libs.dev_env import DevEnv
from libs.cortex_db import CortexDb

# To Run these tests, you must set the cortex_password and CORTEX_SERVICE_ENABLED environment variables
@pytest.mark.skipif('CORTEX_SERVICE_ENABLED' not in os.environ, reason='requires a Synapse database connection')
class TestTagsRoute(AsyncHTTPTestCase):
    """Tags test cases."""

    tagname = 'int.test4'

    def get_headers(self):
        h = tornado.httputil.HTTPHeaders(
            { 'Content-Type': 'application/json',
              'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
              'X-User': '{"userId": 1000, "email": "george@example.com"}' })
        return h


    def get_app(self):
        dir = find_config_dir()
        set_root_dir(dir)
        set_profile('test_e2e')
        # if get_config('add_test_data'):
        #     devenv = DevEnv(CortexDb(logging.getLogger('synapse'), True))
        #     await devenv.add()
        return server.make_app2()

    def node_exists(self, type, property):
        guid = ''
        try:
            response = self.fetch('/src/v1/synapse/tufos/{}={}'.format(type, property),
                                  method='GET',
                                  headers=self.get_headers(),
                                  raise_error=True)
            if response.code >= 200 and response.code < 300:
                json_body = escape.json_decode(response.body)
                guid = json_body['data']['guid']
        except tornado.httpclient.HTTPError:
            guid = ''
        return guid

    def add_node(self, type, property):

        post_body = {
            'name': '{}={}'.format(type, property),
            'tags': [TestTagsRoute.tagname],
        }
        json_body = escape.json_encode(post_body)

        was_added = False
        try:
            response = self.fetch('/src/v1/synapse/tufos',
                                  method='POST',
                                  headers=self.get_headers(),
                                  body=json_body,
                                  raise_error=True)
            if response.code >= 200 and response.code < 300:
                was_added = True
        except tornado.httpclient.HTTPError:
            was_added = False
        return was_added

    def delete_node(self, guid):
        was_deleted = False
        try:
            response = self.fetch('/src/v1/synapse/tufos/{}'.format(guid),
                                  method='DELETE',
                                  headers=self.get_headers(),
                                  raise_error=True)
            if response.code >= 200 and response.code < 300:
                was_deleted = True
        except tornado.httpclient.HTTPError:
            was_deleted = False
        return was_deleted

    def test_add_tag(self):
        """Test adding a new tag."""
        post_args = { 'name': TestTagsRoute.tagname,
                      'title': 'The beetle and the blue fence',
                      'doc': 'The quick black beetle jumped over the blue fence' }
        json_body = escape.json_encode(post_args)
        h = tornado.httputil.HTTPHeaders(
            { 'Content-Type': 'application/json',
              'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
              'X-User': '{"userId": 1000, "email": "george@example.com"}' })

        should_add = False
        try:
            response = self.fetch('/src/v2/synapse/tags/{}'.format(TestTagsRoute.tagname),
                                  method='GET',
                                  headers=h)
            if response.code >= 200 and  response.code < 300:
                should_add = False
            elif response.code == 410:
                should_add = True
        except Exception as err:
            should_add = True

        if should_add:
            response = self.fetch('/src/v2/synapse/tags',
                                  method='POST',
                                  body=json_body,
                                  headers=h)
            result = json.loads(response.body)
            assert response.code == 200
            assert result['msg'] == "success"
            assert 'data' in result
            assert 'created' in result['data']
            assert result['data']['name'] == post_args['name']
            assert result['data']['created']

    def test_get_tag(self):
        """Test adding a new tag."""
        h = tornado.httputil.HTTPHeaders({
            'Content-Type': 'application/json',
            'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
            'X-User': '{"userId": 1000, "email": "george@example.com"}' })

        response = self.fetch('/src/v2/synapse/tags/{}'.format(TestTagsRoute.tagname),
                              method='GET',
                              headers=h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
        assert 'data' in result
        assert 'created' in result['data']
        assert 'title' in result['data']
        assert 'doc' in result['data']

    def test_del_tag(self):
        """Test adding a new tag."""
        h = tornado.httputil.HTTPHeaders({
            'Content-Type': 'application/json',
            'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
            'X-User': '{"userId": 1000, "email": "george@example.com"}' })

        response = self.fetch('/src/v2/synapse/tags/{}'.format(TestTagsRoute.tagname),
                              method='DELETE',
                              headers=h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
        assert 'data' in result
        assert 'created' in result['data']

    def test_update_tag(self):
        """Test adding a new tag."""
        post_args = {
            'title': 'The bird and the green fence',
            'doc': 'The quick blue bird flew over the green fence',
        }
        json_body = escape.json_encode(post_args)
        h = tornado.httputil.HTTPHeaders({
            'Content-Type': 'application/json',
            'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
            'X-User': '{"userId": 1000, "email": "george@example.com"}' })

        response = self.fetch('/src/v2/synapse/tags/{}'.format(TestTagsRoute.tagname),
                              method='PUT',
                              body=json_body,
                              headers=h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
        assert 'data' in result
        assert 'title' in result['data']
        assert 'doc' in result['data']
        assert result['data']['name'] == TestTagsRoute.tagname
        assert result['data']['created']

    def test_tags_nodes_combination(self):
        '''Test adding a new tag.'''
        post_args = { 'name': TestTagsRoute.tagname,
                      'title': 'The beetle and the blue fence',
                      'doc': 'The quick black beetle jumped over the blue fence' }
        json_body = escape.json_encode(post_args)
        h = tornado.httputil.HTTPHeaders(
            { 'Content-Type': 'application/json',
              'X-TransactionId': '0AXB9V5GUdg8m4om10jCMeUr',
              'X-User': '{"userId": 1000, "email": "george@example.com"}' })

        should_add = False
        try:
            response = self.fetch('/src/v2/synapse/tags/{}'.format(TestTagsRoute.tagname),
                                  method='GET',
                                  headers=h)
            if response.code >= 200 and  response.code < 300:
                should_add = False
            elif response.code == 410:
                should_add = True
        except Exception as err:
            should_add = True

        if should_add:
            response = self.fetch('/src/v2/synapse/tags',
                                  method='POST',
                                  body=json_body,
                                  headers=h)
            result = json.loads(response.body)
            assert response.code == 200
            assert result['msg'] == 'success'
            assert 'data' in result
            assert 'created' in result['data']
            assert result['data']['name'] == post_args['name']
            assert result['data']['created']


        ipv4_nodes = [
            {'guid': '', 'property': '34.34.34.34'},
            {'guid': '', 'property': '35.35.35.35'},
        ]
        for node in ipv4_nodes:
            guid = self.node_exists('inet:ipv4', node['property'])
            if not guid:
                guid = self.add_node('inet:ipv4', node['property'])
            node['guid'] = guid

        # Delete the tags
        response = self.fetch('/src/v2/synapse/tags/{}'.format(TestTagsRoute.tagname),
                              method='DELETE',
                              headers=h)
        result = json.loads(response.body)
        assert response.code == 200
        assert result['msg'] == 'success'
        assert 'data' in result
        assert 'created' in result['data']

        # Delete the nodes
        for node in ipv4_nodes:
            assert node['guid']
            if self.node_exists('inet:ipv4', node['property']):
                del_result = self.delete_node(node['guid'])
