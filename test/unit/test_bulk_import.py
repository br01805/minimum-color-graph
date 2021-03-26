import pytest
import logging
from libs.config import get_config, set_root_dir, set_profile, find_config_dir
from libs.synapse_models.bulk_import import BulkImport, ParameterError
import json


def build_tags_set(ioc_list):
    """Build a list of unique tags from the request"""
    tags = set()
    assert 'nodes' in ioc_list
    nodes = ioc_list['nodes']
    if not isinstance(nodes, dict):
        raise ParameterError('Identifier dictionary keys')
    for id in nodes:
        the_node = nodes[id]
        if 'tags' not in the_node:
            raise ParameterError('identifier.tags', id)
        if not isinstance(the_node['tags'], list):
            raise ParameterError('Identifier tags array', id)
        tags.update(the_node['tags'])
    return tags


@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestBulkImport():

    def assert_response(self, result, expected_status = 0):
        assert result
        assert 'status' in result
        assert result['status'] == expected_status
        assert 'msg' in result
        assert 'data' in result
        assert isinstance(result['data'], dict)
        assert 'elapsed' in result['data']
        assert 'errors' in result['data']
        assert 'nodesInserted' in result['data']
        assert 'bytesTotal' in result['data']
        assert 'tagsApplied' in result['data']

    def assert_first_error(self, result, expected_id_len, expected_list_len):
        assert len(result['data']['errors']) == expected_id_len
        err = result['data']['errors']
        my_keys = list(err.keys())
        id = my_keys[0]
        error1 = err[my_keys[0]]
        assert id
        assert error1
        assert isinstance(error1, list)
        assert len(error1)  == expected_list_len
        return error1[0]

    @pytest.mark.asyncio
    async def test_successful_request(self):
        regular_data = {}
        regular_data['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                    '9b95c3720409900102230a3ec7304d7a': 'hash:md5'
                },
                'tags': ['tag1']
            },
            'line2': {
                'iocs': {
                    '9f9e8e8ed9ab323b064f0d699f41faa070884ef1': 'hash:sha1',
                    'dd7f812383476c2387ecc5cb6940cdd0': 'hash:md5'
                },
                'tags': ['tag1', 'tag2']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, regular_data, ['tag1', 'tag2'], ['tag1', 'tag2'])
        result = await bi.run()
        self.assert_response(result)
        assert result['msg'] == 'success'
        data = result['data']
        assert len(data['errors']) == 0
        assert data['nodesInserted'] == 4
        assert data['tagsApplied'] == 6
        assert data['bytesTotal'] > 200

    @pytest.mark.asyncio
    async def test_unregistered_tags(self):
        unregistered_tag = {}
        unregistered_tag['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1'
                },
                'tags': ['tag1', 'tag2', 'tag3']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, unregistered_tag, ['tag1', 'tag2'], ['tag1', 'tag2'])
        result = await bi.run()
        self.assert_response(result, -100)

    @pytest.mark.asyncio
    async def test_missing_nodes_property(self):
        no_nodes_property = {}
        no_nodes_property['Nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                    '9b95c3720409900102230a3ec7304d7a': 'hash:md5'
                },
                'tags': ['tag1']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, no_nodes_property, ['tag1', 'tag2'], ['tag1', 'tag2'])
        with pytest.raises(ParameterError) as e_info:
            result = await bi.run()

    @pytest.mark.asyncio
    @pytest.mark.skip("010x Test")
    async def test_missing_property_identifier(self):
        no_identifier_property = {}
        no_identifier_property['nodes'] = [
            {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                    '9b95c3720409900102230a3ec7304d7a': 'hash:md5'
                },
                'tags': ['tag1']
            }
        ]
        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, no_identifier_property, ['tag1', 'tag2'], ['tag1', 'tag2'])
        with pytest.raises(ParameterError) as e_info:
            result = await bi.run()
        msg = str(e_info)
        assert msg.find('missing') > 0
        print(msg)

    @pytest.mark.asyncio
    async def test_missing_property_iocs(self):
        missing_iocs_property = {}
        missing_iocs_property['nodes'] = {
            'line1': {
                'Iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                    '9b95c3720409900102230a3ec7304d7a': 'hash:md5'
                },
                'tags': ['tag1']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, missing_iocs_property, ['tag1', 'tag2'], ['tag1', 'tag2'])
        with pytest.raises(ParameterError) as e_info:
            result = await bi.run()

    @pytest.mark.asyncio
    async def test_missing_property_tags(self):
        no_tags_property = {}
        no_tags_property['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                    '9b95c3720409900102230a3ec7304d7a': 'hash:md5'
                },
                'Tags': ['tag1']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, no_tags_property, ['tag1', 'tag2'], ['tag1', 'tag2'])
        with pytest.raises(ParameterError) as e_info:
            result = await bi.run()

    @pytest.mark.asyncio
    @pytest.mark.skip("010x Test")
    async def test_bad_ioc_form(self):
        bad_form = {}
        bad_form['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha2',
                },
                'tags': ['tag1']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, bad_form, ['tag1', 'tag2'], ['tag1', 'tag2'])
        result = await bi.run()
        self.assert_response(result, -200)
        assert result['msg'] == 'import_failure'
        first_err = self.assert_first_error(result, 1, 1)
        assert result['data']['bytesTotal'] == 0
        assert result['data']['nodesInserted'] == 0
        assert result['data']['tagsApplied'] == 0
        assert first_err.find('NoSuchForm') != -1

    @pytest.mark.asyncio
    @pytest.mark.skip("010x Test")
    async def test_partial_success(self):
        bad_form = {}
        bad_form['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha2',
                    'bc38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                },
                'tags': ['tag1']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, bad_form, ['tag1', 'tag2'], ['tag1', 'tag2'])
        result = await bi.run()
        self.assert_response(result, 1)
        assert result['msg'] == 'partial_success'
        first_err = self.assert_first_error(result, 1, 1)
        assert first_err.find('NoSuchForm') != -1

    @pytest.mark.asyncio
    @pytest.mark.skip("010x Test")
    async def test_bad_ioc_value(self):
        bad_value = {}
        bad_value['nodes'] = {
            'line1': {
                'iocs': {
                    'xc38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                },
                'tags': ['tag1']
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, bad_value, ['tag1', 'tag2'], ['tag1', 'tag2'])
        result = await bi.run()
        self.assert_response(result, -200)
        assert result['msg'] == 'import_failure'
        first_err = self.assert_first_error(result, 1, 1)
        assert first_err.find('BadTypeValu') != -1

    @pytest.mark.asyncio
    async def test_bad_tags_type(self):
        bad_tags_type = {}
        bad_tags_type['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                },
                'tags': {'tag1', 'tag2'}
            }
        }

        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, bad_tags_type, ['tag1', 'tag2'], ['tag1', 'tag2'])
        with pytest.raises(ParameterError) as e_info:
            result = await bi.run()

    @pytest.mark.asyncio
    async def test_duplicate_iocs(self):
        duplicate_iocs = {}
        duplicate_iocs['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                },
                'tags': ['tag1']
            },
            'line2': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                },
                'tags': ['tag1']
            }
        }
        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, duplicate_iocs, ['tag1'], ['tag1'])
        result = await bi.run()
        self.assert_response(result)
        assert result['msg'] == 'success'
        data = result['data']
        assert len(data['errors']) == 0
        assert data['nodesInserted'] == 2
        assert data['tagsApplied'] == 2

    @pytest.mark.asyncio
    @pytest.mark.skip("010x Test")
    async def test_duplicate_iocs_single_invalid(self):
        duplicate_iocs = {}
        duplicate_iocs['nodes'] = {
            'line1': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha1',
                },
                'tags': ['tag1']
            },
            'line2': {
                'iocs': {
                    'ac38e29a88020b7b7125c39b90e579d1455f0989': 'hash:sha2',
                },
                'tags': ['tag1']
            }
        }
        logger = logging.getLogger(__name__)
        bi = BulkImport(logger, duplicate_iocs, ['tag1'], ['tag1'])
        result = await bi.run()
        self.assert_response(result, 1)
        assert result['msg'] == 'partial_success'
        data = result['data']
        assert len(data['errors']) == 1
        assert data['nodesInserted'] == 1
        assert data['tagsApplied'] == 1

    @pytest.mark.skip(reason="no way of currently testing this")
    @pytest.mark.asyncio
    async def test_large_upload(self):
        filename = '/home/ddennerline/Desktop/bulk-import.txt'

        with open(filename) as json_data:
            d = json.load(json_data)
            print(d)
        logger = logging.getLogger(__name__)
        new_tags = build_tags_set(d)
        bi = BulkImport(logger, d, new_tags, ['tag1', 'tag2'])
        result = await bi.run()
        self.assert_response(result)
