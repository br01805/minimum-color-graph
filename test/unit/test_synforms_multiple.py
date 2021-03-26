import pytest
import logging
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb
from helpers.indicator_validate import IndicatorValidate
from libs.synapse_nodes import Tufo
import helpers.http_errors as errors

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestSynapseNodes:
    body_valid = {
        'tufos': [
            {'type': 'inet:url', 'property': 'http://www.example.com/index.html'},
        ]
    }

    body_duplicate = {
        'tufos': [
            {'type': 'inet:url', 'property': 'http://www.example.com/index.html'},
            {'type': 'inet:url', 'property': 'http://www.example.com/index.html'}
        ]
    }

    body_bad1 = {
        'tufos': [
            {'form1': 'inet:url', 'property': 'http://www.example.com/index.html'},
        ]
    }

    body_bad2 = {
        'tufos': [
            {'type': 'inet:url', 'prop1': 'http://www.example.com/index.html'},
        ]
    }

    body_bad3 = {'type': 'inet:url', 'prop1': 'http://www.example.com/index.html'}

    body_bad4 = {
        'tufos':
            {'type': 'inet:url', 'prop1': 'http://www.example.com/index.html'},
    }

    @pytest.mark.asyncio
    async def test_add_node_valid(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        result = await syn_tufo.add_nodes(TestSynapseNodes.body_valid)
        assert 'data' in result
        assert isinstance(result['data'], list)
        assert len(result['data']) == 1

        added_rec = result['data'][0]
        assert {'msg', 'data', 'status'} <= added_rec.keys()
        assert added_rec['msg'] == 'success'
        assert added_rec['status'] == 0
        assert isinstance(added_rec['data'], dict)

        added_rec = added_rec['data']
        assert {'guid', 'type', 'property', 'secondary_property', 'tags', 'tag_tree'} <= added_rec.keys()
        assert added_rec['type'] == TestSynapseNodes.body_valid['tufos'][0]['type']
        assert added_rec['property'] == TestSynapseNodes.body_valid['tufos'][0]['property']

    @pytest.mark.asyncio
    async def test_add_node_duplicate(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        result = await syn_tufo.add_nodes(TestSynapseNodes.body_duplicate)

        added_rec = result['data'][0]
        assert {'msg', 'data', 'status'} <= added_rec.keys()
        assert added_rec['msg'] == 'success'
        assert added_rec['status'] == 0
        assert isinstance(added_rec['data'], dict)

        # Move down to restful result node
        added_rec = added_rec['data']
        assert {'type', 'property', 'guid', 'created'} <= added_rec.keys()
        assert added_rec['type'] == TestSynapseNodes.body_duplicate['tufos'][0]['type']
        assert added_rec['property'] == TestSynapseNodes.body_duplicate['tufos'][0]['property']

        added_rec = result['data'][1]
        assert {'msg', 'data', 'status'} <= added_rec.keys()
        assert added_rec['msg'] == 'duplicate'
        assert added_rec['status'] == 1
        assert isinstance(added_rec['data'], dict)

        added_rec = added_rec['data']
        assert added_rec['type'] == TestSynapseNodes.body_duplicate['tufos'][1]['type']
        assert added_rec['property'] == TestSynapseNodes.body_duplicate['tufos'][1]['property']

    @pytest.mark.asyncio
    async def test_add_node_parameter_error1(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        with pytest.raises(errors.ParameterError):
            await syn_tufo.add_nodes(TestSynapseNodes.body_bad1)

    @pytest.mark.asyncio
    async def test_add_node_parameter_error2(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        with pytest.raises(errors.ParameterError):
            await syn_tufo.add_nodes(TestSynapseNodes.body_bad2)

    @pytest.mark.asyncio
    async def test_add_node_parameter_error3(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        with pytest.raises(errors.ParameterError):
            await syn_tufo.add_nodes(TestSynapseNodes.body_bad3)

    @pytest.mark.asyncio
    async def test_add_node_parameter_error4(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        with pytest.raises(errors.ParameterError):
            await syn_tufo.add_nodes(TestSynapseNodes.body_bad4)

    def test_generate_guid(self):
        syn_tufo = Tufo(logging.getLogger(__name__))
        result = syn_tufo.generate_iden_guid(('inet:fqdn', 'www.example.com'))
        assert 'data' in result
        assert isinstance(result['data'], str)
        validator = IndicatorValidate()
        assert validator.is_syn_guid(result['data'])

    @pytest.mark.asyncio
    async def test_search_nodes(self):
        syn_tufo = Tufo(logging.getLogger(__name__))

        query_valid = {
            'tufos': [
                {'type': 'inet:url', 'property': 'http://www.example.com/index.html'},
                {'type': 'inet:url', 'property': 'http://www.hello.com'},
                {'type': 'inet:fqdn', 'property': 'www.example.com'},
                {'type': 'inet:fqdn', 'property': 'www.hello.com'},
                {'type': 'inet:fqdn', 'property': 'www.bill.com'},
            ]
        }

        result = await syn_tufo.search_nodes(query_valid,
                                             (('inet:url', 'http://www.example.com/index.html'),
                                              ('inet:url', 'http://www.hello.com'),
                                              ('inet:fqdn', 'www.hello.com')))
        assert {'msg', 'data', 'status'} <= result.keys()
        assert isinstance(result['data'], list)
        assert len(result['data']) == 5

        for node in result['data']:
            assert {'type', 'property'} <= node['data'].keys()
            if node['status'] == 0:
                assert 'guid' in node['data']
            if node['data']['property'] == 'www.bill.com':
                assert(node['msg'] == 'missing' and node['status'] == 1)

    @pytest.mark.asyncio
    async def test_search_tcp_udp4(self):
        syn_tufo = Tufo(logging.getLogger(__name__))

        query_valid = {
            'tufos': [
                {'type': 'inet:server', 'property': 'tcp://10.10.10.10:80'},
                {'type': 'inet:server', 'property': 'udp://10.10.10.10:80'},
            ]
        }

        result = await syn_tufo.search_nodes(query_valid,
                                             (('inet:server', 'tcp://10.10.10.10:80'),
                                              ('inet:server', 'udp://10.10.10.10:80')
                                             ))
        assert {'msg', 'data', 'status'} <= result.keys()
        assert isinstance(result['data'], list)
        assert len(result['data']) == 2
        assert any(filter(lambda x: x['data']['property'] == 'tcp://10.10.10.10:80', result['data']))

    @pytest.mark.asyncio
    async def test_search_tcp_udp4_one_missing(self):
        """Test how udp/tcp 4 with duplicate values are handled. Because of the way that Synapse is queried for
         multiple indicators, the response handling is customized to produce a found/not-found indication."""
        syn_tufo = Tufo(logging.getLogger(__name__))

        query_valid = {
            'tufos': [
                {'type': 'inet:server', 'property': 'tcp://10.10.10.10:80'},
                {'type': 'inet:server', 'property': 'udp://10.10.10.10:80'},
            ]
        }

        result = await syn_tufo.search_nodes(query_valid,
                                             (('inet:server', 'tcp://10.10.10.10:80'),
                                             ))
        assert {'msg', 'data', 'status'} <= result.keys()
        assert isinstance(result['data'], list)
        assert len(result['data']) == 2
        for node in result['data']:
            assert {'type', 'property'} <= node['data'].keys()
            if node['status'] == 0:
                assert 'guid' in node['data']

    @pytest.mark.asyncio
    async def test_search_node_missing_single(self):
        """Test searching for a single missing node"""
        syn_tufo = Tufo(logging.getLogger(__name__))

        query_valid = {
            'tufos': [
                {'type': 'inet:fqdn', 'property': 'www.drevil.biz'},
            ]
        }

        result = await syn_tufo.search_nodes(query_valid)
        assert 'data' in result
        assert isinstance(result['data'], list)
        assert len(result['data']) == 1

    @pytest.mark.asyncio
    async def test_delete_nodes(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:url', 'http://www.example.com/index.html'),
                                                        ('inet:fqdn', 'www.hello.com'))
                                                       )
            guids_list.append('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
            result = await syn_tufo.del_nodes(guids_list)
            assert 'data' in result
            assert isinstance(result['data'], list)
            assert len(result['data']) == 3

        validator = IndicatorValidate()
        is_guid_found = False
        for node in result['data']:
            assert {'guid', 'status', 'details'} <= node.keys()
            assert validator.is_syn_guid(node['guid'])
            if node['guid'] == '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff':
                assert node['status'] == 1
                is_guid_found = True
        assert is_guid_found
