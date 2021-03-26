import pytest
import logging
from libs.config import get_config, set_root_dir, set_profile, find_config_dir
from libs.synapse_models.tufo_map import *
import helpers.http_errors as errors


def HttpQueryArgs():
    def __init__(self, the_list):
        self.the_list = the_list

    def get(self, name):
        return self.list[name]

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.skip(reason='Experimental')
class TestTufoObjectMapping():

    ip_url = '/src/v2/synapse/nodes/ipaddr'
    no_json_body = None
    no_get_query_arg_cb = None

    class TestIpAddr:
        def test_from_repr(self):
            ip_addr = InetIpAddr.from_repr('1.1.1.1')

        def test_from_json(self):
            ip_addr = InetIpAddr.from_repr({ 'valu': '1.1.1.1', 'cc': 129 })

        def test_to_syn(self):
            ip_addr = InetIpAddr.from_repr({ 'valu': '1.1.1.1', 'cc': 129 })
            ip_addr.print_syn_create()
            ip_addr.print_syn_update()
            ip_addr.print_syn_get()
            ip_addr.print_syn_delete()

    class TestRouting:
        def test_good_indicator(self):
            tufo_map = TufoMap(logging.getLogger(__name__))
            functor = tufo_map.new_operation('GET', TestTags.ip_url + '/10.1.1.1', TestTags.no_json_body, TestTags.no_get_query_arg_cb)

        def test_bad_indicator(self):
            tufo_map = TufoMap(logging.getLogger(__name__))
            tufo_map.new_operation('GET', '/src/v2/synapse/nodes/unknown', TestTags.no_json_body, TestTags.no_get_query_arg_cb)

        def test_bad_method(self):
            tufo_map = TufoMap(logging.getLogger(__name__))
            tufo_map.new_operation('PATCH', '/src/v2/synapse/nodes/ipaddr', TestTags.no_json_body, TestTags.no_get_query_arg_cb)

    class TestGetMethod:
        def test_ipv4_get(self):
            url = '%s/4.4.4.4' % TestTags.ip_url
            tufo_map = TufoMap(logging.getLogger(__name__))
            functor = tufo_map.new_operation('GET', url, TestTags.no_json_body, TestTags.no_get_query_arg_cb)
            json_result = functor.run()

        def test_ipv6_get(self):
            url = '%s/fe80::e985:2178:c137:8a88' % TestTags.ip_url
            tufo_map = TufoMap(logging.getLogger(__name__))
            functor = tufo_map.new_operation('GET', url, TestTags.no_json_body, TestTags.no_get_query_arg_cb)
            json_result = functor.run()

        def test_ipv4_get_bad_value(self):
            url = '%s/a' % TestTags.ip_url
            tufo_map = TufoMap(logging.getLogger(__name__))
            with pytest.raises(errors.ParameterError):
                tufo_map.new_operation('GET', url, TestTags.no_json_body, TestTags.no_get_query_arg_cb)


    class TestListMethod:
        def test_ipv4_list(self):
            url = TestTags.ip_url
            tufo_map = TufoMap(logging.getLogger(__name__))
            functor = tufo_map.new_operation('GET', url, TestTags.no_json_body, TestTags.no_get_query_arg_cb)
            json_result = functor.run()


    class TestPostMethod:
        def test_ipv4_post(self):
            url = TestTags.ip_url
            tufo_map = TufoMap(logging.getLogger(__name__))
            json_body = {
                'asn': 100,
                'type': 'internal'
            }
            functor = tufo_map.new_operation('POST', url, json_body, TestTags.no_get_query_arg_cb)
            json_body = functor.run()


    class TestPutMethod:
        def test_ipv4_put(self):
            url = TestTags.ip_url
            tufo_map = TufoMap(logging.getLogger(__name__))
            json_body = {
                'type': 'external'
            }
            functor = tufo_map.new_operation('PUT', url, json_body, TestTags.no_get_query_arg_cb)
            json_body = functor.run()
