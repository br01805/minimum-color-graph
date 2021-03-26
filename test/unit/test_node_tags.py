import pytest

import pytest
import logging
from libs.config import get_config, set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb
from libs.synapse_models.node_tags import NodeTagsApplyRemove
from libs.synapse_nodes import Tufo
from libs.db_node_history import DbNodeHistory, ArangoConfig
from libs.userctx import OperationSource, UserContext
import helpers.http_errors as errors

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestNodeTags:
    async def test_apply_node_valid(self):
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1', 'int.tag2']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list, True, cortex_db)

        async with cortex_db:
            await node_tags.add_test_nodes(inet_ipv4, tag_list)
            node_tags = await node_tags.run()
            assert {'status', 'msg', 'data'} <= node_tags.keys()
            assert node_tags['msg'] == 'success'
            assert node_tags['status'] == 0
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag1', '#int.tag2']

    async def test_apply_node_guid_valid(self):
        """Test applying tags using a GUID instead of name=value"""
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1', 'int.tag2']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        logger = logging.getLogger(__name__)

        async with cortex_db:
            tufo = Tufo(logger, cortex_db)
            add_result = await tufo.add_single_raw('inet:ipv4', '84.84.84.84', None, None)
            node_tags = NodeTagsApplyRemove(logger, add_result['data']['guid'], tag_list, True, cortex_db)
            add_results = await node_tags.add_test_nodes(inet_ipv4, tag_list)
            node_tags = await node_tags.run()
            assert {'status', 'msg', 'data'} <= node_tags.keys()
            assert node_tags['msg'] == 'success'
            assert node_tags['status'] == 0
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag1', '#int.tag2']

    async def test_apply_remove_node_guid_valid(self):
        """Test applying tags using a GUID instead of name=value"""
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1', 'int.tag2']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        logger = logging.getLogger(__name__)

        async with cortex_db:
            tufo = Tufo(logger, cortex_db)  # Use this API to get a GUID
            add_result = await tufo.add_single_raw('inet:ipv4', '84.84.84.84', None, None)
            add_node_tags = NodeTagsApplyRemove(logger, add_result['data']['guid'], tag_list, True, cortex_db)
            rm_node_tags = NodeTagsApplyRemove(logger, add_result['data']['guid'], tag_list, False, cortex_db)
            await add_node_tags.add_test_nodes(inet_ipv4, tag_list)
            add_node_result = await add_node_tags.run()
            assert {'status', 'msg', 'data'} <= add_node_result.keys()
            assert add_node_result['msg'] == 'success'
            assert add_node_result['status'] == 0
            assert list(add_node_result['data']['tags'].keys()) == ['#int.tag1', '#int.tag2']

            rm_results = await rm_node_tags.run()
            assert {'status', 'msg', 'data'} <= rm_results.keys()
            assert rm_results['msg'] == 'success'
            assert rm_results['status'] == 0
            assert list(rm_results['data']['tags'].keys()) == []


    async def test_apply_node_raw_valid(self):
        inet_ipv4_synform = 'inet:ipv4'
        inet_ipv4_synvalu = '85.85.85.85'
        tag_list = ['int.tag1', 'int.tag2']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), (inet_ipv4_synform, inet_ipv4_synvalu), tag_list, True, cortex_db)

        async with cortex_db:
            await node_tags.add_test_nodes((inet_ipv4_synform, inet_ipv4_synvalu), tag_list)
            node_tags = await node_tags.run()
            assert {'status', 'msg', 'data'} <= node_tags.keys()
            assert node_tags['msg'] == 'success'
            assert node_tags['status'] == 0
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag1', '#int.tag2']

    async def test_apply_node_date_valid(self):
        """Test the Tag Timestamp feature to ensure the dates are valid"""

        def get_tag(tag):
            pos = tag.find('=')
            new_tag = tag[0:pos] if pos >= 0 else tag
            return new_tag.strip()

        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1=(2017/01/01, 2017/01/31)', 'int.tag2 = 2020/01/01', 'int.tag3']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list, True, cortex_db)

        async with cortex_db:
            await node_tags.add_test_nodes(inet_ipv4, [get_tag(tag) for tag in tag_list])
            node_tags = await node_tags.run()
            assert {'status', 'msg', 'data'} <= node_tags.keys()
            assert node_tags['msg'] == 'success'
            assert node_tags['status'] == 0
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag1', '#int.tag2', '#int.tag3']
            assert node_tags['data']['tags']['#int.tag1'] == ('2017-01-01T00:00:00Z', '2017-01-31T00:00:00Z')
            assert node_tags['data']['tags']['#int.tag2'] == ('2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
            assert node_tags['data']['tags']['#int.tag3'] == (None, None)

    async def test_remove_node_valid(self):
        """Test the build remove query algorithm using different types of tags"""
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.level1.tag1', 'int.level2.tag1']
        tag_rm_list = ['int.level1.tag1']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list, True, cortex_db)
        node_rm_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_rm_list, False, cortex_db)

        async with cortex_db:
            await node_tags.add_test_nodes(inet_ipv4, tag_list)
            node_tags = await node_tags.run()
            assert 'data' in node_tags
            assert isinstance(node_tags['data'], dict)
            assert {'guid', 'type', 'property', 'tags'} <= node_tags['data'].keys()
            assert ['#int.level1.tag1', '#int.level2.tag1'] == list(node_tags['data']['tags'].keys())

            node_tags = await node_rm_tags.run()
            assert 'data' in node_tags
            assert len(node_tags['data']['tags'].keys()) == 1
            assert len(node_tags['data']['tag_tree'].keys()) == 2
            assert {'#int.level2.tag1'} == node_tags['data']['tags'].keys()

    async def test_remove_tag_missing(self):
        """Test removing a tag that is not part of the current list"""
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1', 'int.tag2']
        tag_rm_list = ['int.tag1']

        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_add_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list, True, cortex_db)
        node_rm_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_rm_list, False, cortex_db)

        async with cortex_db:
            await node_add_tags.add_test_nodes(inet_ipv4, tag_list)
            node_tags = await node_add_tags.run()
            assert {'status', 'msg', 'data'} <= node_tags.keys()
            assert node_tags['msg'] == 'success'
            assert node_tags['status'] == 0
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag1', '#int.tag2']

            node_tags = await node_rm_tags.run()
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag2']

            node_tags = await node_rm_tags.run()
            assert list(node_tags['data']['tags'].keys()) == ['#int.tag2']

    async def test_build_remove_query(self):
        """Test the build remove query algorithm using different types of tags"""

        syn_rsp = ('node', (
            ('inet:ipv4', 1414812756),
            {'iden': '20ed595bd3e372b4a894c4fd12d01c96c5a101e1d058c952f93a23eb334fdd82',
             'tags': {
                 'int': (None, None),
                 'int.tlp': (None, None),
                 'thr': (None, None),
                 'thr.test1': (None, None),
                 'int.tlp.white': (None, None),
                 'code': (None, None),
                 'code.level1': (None, None),
                 'code.level1.tag2': (None, None),
                 'code.level1.tag1': (None, None),
             },
             'props': {'type': 'unicast',
                       'asn': 0,
                       'loc': '??',
                       '.created': 1569627743337
                      },
             'tagprops': {},
             'path': {'nodes': ('20ed595bd3e372b4a894c4fd12d01c96c5a101e1d058c952f93a23eb334fdd82',)}
            }))

        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_rm_list = ['code.level1.tag1', 'int.tlp.white']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_rm_list, False, cortex_db)
        result = node_tags.build_remove_query(syn_rsp)
        assert result == '-#code.level1.tag1 -#int.tlp.white -#int.tlp -#int'

    async def test_build_remove_tag_missing_from_node(self):

        syn_rsp = ('node', (
            ('inet:ipv4', 1414812756),
            {'iden': '20ed595bd3e372b4a894c4fd12d01c96c5a101e1d058c952f93a23eb334fdd82',
             'tags': {
                 'int': (None, None),
                 'int.tlp': (None, None),
                 'thr': (None, None),
                 'thr.test1': (None, None),
                 'int.tlp.white': (None, None),
                 'code': (None, None),
                 'code.level1': (None, None),
                 'code.level1.tag2': (None, None),
                 'code.level1.tag1': (None, None),
             },
             'props': {'type': 'unicast',
                       'asn': 0,
                       'loc': '??',
                       '.created': 1569627743337
                      },
             'tagprops': {},
             'path': {'nodes': ('20ed595bd3e372b4a894c4fd12d01c96c5a101e1d058c952f93a23eb334fdd82',)}
            }))

        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_rm_list = ['code.level3.tag1', 'int.tlp.white']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_rm_list, False, cortex_db)
        result = node_tags.build_remove_query(syn_rsp)
        assert result == '-#int.tlp.white -#int.tlp -#int'

    async def test_build_remove_multiple_tags_node(self):
        """Remove multiple tag from a single node"""
        syn_rsp = ('node', (
            ('inet:ipv4', 1414812756),
            {'iden': '20ed595bd3e372b4a894c4fd12d01c96c5a101e1d058c952f93a23eb334fdd82',
             'tags': {
                 'int': (None, None),
                 'int.tlp': (None, None),
                 'thr': (None, None),
                 'thr.test1': (None, None),
                 'int.tlp.white': (None, None),
                 'code': (None, None),
                 'code.level1': (None, None),
                 'code.level1.tag2': (None, None),
                 'code.level1.tag1': (None, None),
                 'code.level2.tag1': (None, None),
             },
             'props': {'type': 'unicast',
                       'asn': 0,
                       'loc': '??',
                       '.created': 1569627743337
                      },
             'tagprops': {},
             'path': {'nodes': ('20ed595bd3e372b4a894c4fd12d01c96c5a101e1d058c952f93a23eb334fdd82',)}
            }))

        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_rm_list = ['code.level1.tag1', 'code.level1.tag2', 'int.tlp.white']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_rm_list, False, cortex_db)
        result = node_tags.build_remove_query(syn_rsp)
        assert result == '-#code.level1.tag1 -#code.level1 -#code.level1.tag2 -#int.tlp.white -#int.tlp -#int'

    async def test_apply_node_missing(self):
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        inet_ipv4_bad = 'inet:ipv4=84.84.84.83'
        tag_list = ['int.tag1', 'int.tag2']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4_bad, tag_list, True, cortex_db)

        async with cortex_db:
            with pytest.raises(errors.ResourceMissingError):
                await node_tags.add_test_nodes(inet_ipv4, tag_list)
                node_tags = await node_tags.run()

    async def test_apply_tag_missing(self):
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1', 'int.tag2']
        tag_list_bad = ['int.tag1', 'int.tag3']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list_bad, True, cortex_db)

        async with cortex_db:
            with pytest.raises(errors.UnregisteredTags) as e_info:
                await node_tags.add_test_nodes(inet_ipv4, tag_list)
                node_tags = await node_tags.run()
            assert str(e_info.value).find('[\'int.tag3\']') >= 0

    async def test_apply_invalid_tag_list_type(self):
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = {'tags': ['int.tag1', 'int.tag2']}
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            with pytest.raises(errors.ParameterError) as e_info:
                node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list, True, cortex_db)
                await node_tags.add_test_nodes(inet_ipv4, tag_list)
            assert str(e_info.value).find('expecting') >= 0
            assert str(e_info.value).find('dict') >= 0

    async def test_apply_node_db_node_history(self):
        inet_ipv4 = 'inet:ipv4=84.84.84.84'
        tag_list = ['int.tag1', 'int.tag2']
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        userctx = UserContext(100, 'george@example.com', '', op_source=OperationSource.maxmind)
        node_tags = NodeTagsApplyRemove(logging.getLogger(__name__), inet_ipv4, tag_list, True, cortex_db,
                                        db_node_history, userctx)
        async with cortex_db:
            await node_tags.add_test_nodes(inet_ipv4, tag_list)
            node_tags = await node_tags.run()
