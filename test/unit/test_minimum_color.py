import logging
import pytest
import helpers.quoted_storm_value as qsv
from helpers.synapse_010_format import (sf_get_guid, sf_was_added, sf_get_first_node, sf_get_form_value)
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async
from libs.db_node_history import DbNodeHistory, ArangoConfig
from libs.synapse_nodes import Tufo
from libs.synapse_models.composite_nodes import CreateCompositeNode
from libs.userctx import OperationSource, UserContext
from libs.tranco import TrancoRanked
import helpers.http_errors as errors

def return_user_request():
    return UserContext(100, 'george@example.com', '0AXB9V5GUdg8m4om10jCMeUr', OperationSource.simple)

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.fixture(scope='function')
def node_history():
    cfg = ArangoConfig()
    history_db = DbNodeHistory(logging.getLogger(__name__), cfg)
    yield history_db
    history_db.close()

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

    md5 = 'da498a80ff5a96d69dd86b729c719331'

    def get_guid(self, node):
        value = sf_get_form_value(node)
        #return value[5:] if value.startswith('guid:') else value
        return value

    async def add_filebytes(self, cortex_db, name):
        sha1 = '9a07ebd68a70618b8b47f98d0dd3881c3035e7ff'
        sha256 = '43efc9cc0f306b9c9d81d33dc1701049749d696183eaf051cf90d92609a09d9b'
        sha512 = '1b7d6e3ba7143e2834d3dd89105bba3e0ebb46838ba955e4a2a145e422426515d89e6834aedeef46f44b367d65405c52a542ce88afa3066e4586521b09860fb8'

        syn_query = '[ file:bytes=sha256:{} :name="{}" :mime=application/pdf :md5={} :sha1={} :sha256={} :sha512={} ]'.format(
            sha256, name, TestSynapseNodes.md5, sha1, sha256, sha512)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        added_node = sf_get_first_node(ask_results)
        return (sf_get_guid(added_node), self.get_guid(added_node), sha1)

    async def add_url(self, cortex_db, url):
        syn_query = '[ inet:url="{}" ]'.format(url)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        added_node = sf_get_first_node(ask_results)
        return (sf_get_guid(added_node), sf_get_form_value(added_node))

    async def add_fqdn(self, cortex_db, fqdn):
        syn_query = '[ inet:fqdn={} ]'.format(fqdn)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        added_node = sf_get_first_node(ask_results)
        return (sf_get_guid(added_node), sf_get_form_value(added_node))

    async def create_file_bytes_urlfile(self, cortex_db, logger, fb_guid):
        async with cortex_db:
            url_guids = await self.add_url(cortex_db, 'https://twitter.com/oguzpamuk/status/1160905143593910272?s=20')
            req = {
                'parent': {'type': 'inet:url', 'property': url_guids[1]},
                'child': {'type': 'file:bytes', 'property': fb_guid[1]},
            }

            req = CreateCompositeNode(logger, req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['secondary_property']['url']\
                   == 'https://twitter.com/oguzpamuk/status/1160905143593910272?s=20'
            assert results['data']['secondary_property']['file'] == fb_guid[1]


    async def create_file_bytes_xrefs(self, cortex_db, logger, filename='myreport.pdf'):
        child_indicators = ((self.add_fqdn, 'inet:fqdn', 'www.example.com'),
                            (self.add_url, 'inet:url', 'https://www.dropbox.com/upgrade?oqa=upeao'),
                            )

        async with cortex_db:
            fb_guids = await self.add_filebytes(cortex_db, filename)
            for test_ind in child_indicators:
                guid2 = await test_ind[0](cortex_db, test_ind[2])
                req = {
                    'parent': {'type': 'file:bytes', 'property': fb_guids[1]},
                    'child': {'type': test_ind[1], 'property': guid2[1]},
                }

                req = CreateCompositeNode(logger, req, cortex_db)
                results = await req.run()
                assert {'status', 'msg', 'data'} <= results.keys()
                assert results['data']['secondary_property']['n1'] == ('file:bytes', fb_guids[1])
                assert results['data']['secondary_property']['n2'] == (test_ind[1], guid2[1])
        return fb_guids

    @pytest.mark.asyncio
    async def test_delete_single_node(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:url', 'http://www.example.com/index.html'),
                                                        ('inet:fqdn', 'www.hello.com'))
                                                       )
            assert len(guids_list) == 2
            result = await syn_tufo.del_single_node(guids_list[0])
            assert 'data' in result

    @pytest.mark.asyncio
    async def test_delete_simple_file_bytes_node(self):
        """Test deleting a simple file:bytes node that doesn't have any parent references"""
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            syn_tufo = Tufo(logger, cortex_db)
            for i in range(2):
                fb_guids = await self.add_filebytes(cortex_db,  'example.pdf')
                await self.create_file_bytes_urlfile(cortex_db, logger, fb_guids)
                del_result = await syn_tufo.del_single_node(fb_guids[0])
                assert 'data' in del_result
                ask_results = await read_async(None, cortex_db.conn(), 'hash:md5=%s' % TestSynapseNodes.md5)
                assert(not ask_results)

    @pytest.mark.asyncio
    async def test_delete_complex_file_bytes_node(self):
        """This test evaluates a complex file:bytes relationship containing edge:refs and inet:urlfile nodes."""
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            syn_tufo = Tufo(logger, cortex_db)
            fb_guids = await self.create_file_bytes_xrefs(cortex_db, logger)
            await self.create_file_bytes_urlfile(cortex_db, logger, fb_guids)
            del_result = await syn_tufo.del_single_node(fb_guids[0])
            assert 'data' in del_result
            ask_results = await read_async(None, cortex_db.conn(), 'iden %s | -> edge:refs -> *' % fb_guids[0])
            assert (not ask_results)
            ask_results = await read_async(None, cortex_db.conn(), 'inet:urlfile')
            assert (not ask_results)

    @pytest.mark.asyncio
    async def test_delete_single_missing(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:url', 'http://www.example.com/index.html'),
                                                        ('inet:fqdn', 'www.hello.com'))
                                                      )
            assert len(guids_list) == 2
            with pytest.raises(errors.ResourceMissingError):
                await syn_tufo.del_single_node('112233445566778899aabbccddeeff1122338331bc61e7c7694fc80e2d1d58da')

    @pytest.mark.asyncio
    async def test_set_props(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:ipv4', '9.9.9.9'),
                                                       ))
            result = await syn_tufo.set_props('inet:ipv4=9.9.9.9',
                                              {
                                                  'asn': 1000,
                                                  'latlong': (-12.45,56.78),
                                                  'type': 'internal',
                                                  'loc': 'us',
                                                  '.seen': 'now',
                                                  'tags': ('int.tag1', 'int.tag2')
                                              })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'guid', 'type', 'property', 'secondary_property', 'tags'} <= result['data'].keys()
            assert tuple(result['data']['tags'].keys()) == ('#int.tag1', '#int.tag2')
            assert result['data']['secondary_property']['latlong'] == (-12.45,56.78)
            assert isinstance(result['data']['secondary_property']['seen'], tuple)

    @pytest.mark.asyncio
    async def test_set_props_only_tags(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:ipv4', '9.9.9.9'),
                                                       ))
            result = await syn_tufo.set_props('inet:ipv4=9.9.9.9',
                                              {
                                                  'tags': ('int.tag1', 'int.tag2')
                                              })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'guid', 'type', 'property', 'secondary_property', 'tags'} <= result['data'].keys()
            assert tuple(result['data']['tags'].keys()) == ('#int.tag1', '#int.tag2')

    @pytest.mark.asyncio
    async def test_set_props_raw(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:ipv4', '9.9.9.9'),
                                                       ))
            result = await syn_tufo.set_props(('inet:ipv4', '9.9.9.9'),
                                              {
                                                  'asn': 1000,
                                                  'latlong': (-12.45,56.78),
                                                  'type': 'internal',
                                                  'tags': ('int.tag1', 'int.tag2')
                                              })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'guid', 'type', 'property', 'secondary_property', 'tags'} <= result['data'].keys()
            assert tuple(result['data']['tags'].keys()) == ('#int.tag1', '#int.tag2')
            assert result['data']['secondary_property']['latlong'] == (-12.45,56.78)

            result = await syn_tufo.set_props(result['data']['guid'],
                                              {
                                                  'asn': 2000,
                                                  'latlong': (-33.92483,84.37908),
                                                  'type': 'external',
                                              })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'guid', 'type', 'property', 'secondary_property', 'tags'} <= result['data'].keys()
            assert tuple(result['data']['tags'].keys()) == ('#int.tag1', '#int.tag2')
            assert result['data']['secondary_property']['latlong'] == (-33.92483,84.37908)

    @pytest.mark.asyncio
    async def test_set_props_file_bytes_with_mime_props(self, node_history):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db, db_node_history=node_history,
                            userctx=return_user_request())
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                          (('syn:tag', 'int.tag1'),
                                          ))
            fb_guids = await self.add_filebytes(cortex_db, 'myreport.pdf')
            result = await syn_tufo.set_props(('file:bytes', fb_guids[1]),
                                              {
                                                  'mime:pe:compiled': 1431312336000,
                                                  'tags': ['int.tag1'],
                                              })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'guid', 'type', 'property', 'secondary_property', 'tags'} <= result['data'].keys()
            assert list(result['data']['tags'].keys()) == ['#int.tag1']
            assert result['data']['secondary_property']['mime:pe:compiled'] == 1431312336000

    @pytest.mark.asyncio
    async def test_set_props_tags_only(self, node_history):
        """This test ensures that only an ApplyTags node history record is created"""
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db, db_node_history=node_history,
                            userctx=return_user_request())
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                          (('syn:tag', 'int.tag1'),
                                           ('inet:ipv4', '9.9.9.9')
                                          ))
            result = await syn_tufo.set_props(('inet:ipv4', '9.9.9.9'),
                                              {
                                                  'tags': ['int.tag1'],
                                              })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'guid', 'type', 'property', 'secondary_property', 'tags'} <= result['data'].keys()
            assert list(result['data']['tags'].keys()) == ['#int.tag1']

    @pytest.mark.asyncio
    async def test_set_props_missing(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            with pytest.raises(errors.ResourceMissingError):
                await syn_tufo.set_props('inet:ipv4=9.9.9.9',
                                         {
                                             'asn': 1000,
                                         })
    @pytest.mark.asyncio
    async def test_set_props_invalid_form(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:ipv4', '9.9.9.9'),
                                                       ))
            with pytest.raises(errors.SynapseError):
                await syn_tufo.set_props('bad:ipv4=9.9.9.9',
                                         {
                                             'asn': 1000,
                                         })
    @pytest.mark.asyncio
    async def test_set_props_invalid_prop_name(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                         (('inet:ipv4', '9.9.9.9'),
                                         ))
            with pytest.raises(errors.InvalidSynapseProperties):
                await syn_tufo.set_props('inet:ipv4=9.9.9.9',
                                         {
                                             'badprop': 1000,
                                         })
    @pytest.mark.asyncio
    async def test_set_props_invalid_prop_value(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                          (('inet:ipv4', '9.9.9.9'),
                                          ))
            with pytest.raises(errors.InvalidSynapseProperties):
                await syn_tufo.set_props('inet:ipv4=9.9.9.9',
                                         {
                                             'asn': 'bad property value',
                                         })

    @pytest.mark.asyncio
    async def test_set_props_parameter_error_no_name(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            with pytest.raises(errors.ParameterError):
                await syn_tufo.set_props(None,
                                         {
                                             'asn': 1000,
                                         })

    @pytest.mark.asyncio
    async def test_set_props_parameter_error_no_property_list(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            with pytest.raises(errors.ParameterError):
                await syn_tufo.set_props('inet:ipv4=9.9.9.9', {});

    @pytest.mark.asyncio
    async def test_set_props_parameter_error_no_property_list(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            with pytest.raises(errors.ParameterError):
                await syn_tufo.set_props('inet:ipv4=9.9.9.9', {'tags': []});

    @pytest.mark.asyncio
    async def test_set_props_parameter_error_invalid_property_list_type(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            with pytest.raises(errors.ParameterError):
                await syn_tufo.set_props('inet:ipv4=9.9.9.9', ('name', 'value'));

    @pytest.mark.asyncio
    async def test_get_single_syn_form(self):
        syn_tufo = Tufo(logging.getLogger(__name__))

        adjacent_ref_count = 0
        result = await syn_tufo.get_single('inet:url=http://www.example.com/index.html',
                                           None,
                                           adjacent_ref_count,
                                           (('inet:url', 'http://www.example.com/index.html'),
                                           ))
        assert result
        assert {'guid', 'type', 'property', 'secondary_property'} <= result.keys()
        assert result['type'] == 'inet:url'
        assert result['property'] == 'http://www.example.com/index.html'

        adjacent_ref_count = 0
        result = await syn_tufo.get_single(('inet:url', 'http://www.example.com/index.html'),
                                           None,
                                           adjacent_ref_count,
                                           (('inet:url', 'http://www.example.com/index.html'),
                                           ))
        assert result
        assert {'guid', 'type', 'property', 'secondary_property'} <= result.keys()
        assert result['type'] == 'inet:url'
        assert result['property'] == 'http://www.example.com/index.html'


    @pytest.mark.asyncio
    async def test_get_dns_a_with_refcount(self):
        """This test case checks that getting the references for a DNS:a record works correctly.
        An Synapse syntax error was produced in the file:bytes checking code.
        """
        syn_tufo = Tufo(logging.getLogger(__name__))

        adjacent_ref_count = 1
        result = await syn_tufo.get_single('inet:dns:a=(www.example.com, 56.56.56.56)',
                                           None,
                                           adjacent_ref_count,
                                           (('inet:fqdn', 'www.example.com'),
                                            ('inet:ipv4', '56.56.56.56'),
                                            ('inet:dns:a', '(www.example.com, 56.56.56.56)'),
                                           ))
        assert result
        assert {'guid', 'type', 'property', 'secondary_property', 'adjacent_nodes'} <= result.keys()
        assert result['type'] == 'inet:dns:a'
        assert result['property'] == '(www.example.com, 56.56.56.56)'
        assert len(result['adjacent_nodes']) == 2
        assert result['adjacent_nodes'][0]['type'] == 'inet:fqdn'
        assert result['adjacent_nodes'][0]['property'] == 'www.example.com'
        assert result['adjacent_nodes'][1]['type'] == 'inet:ipv4'
        assert result['adjacent_nodes'][1]['property'] == '56.56.56.56'

    @pytest.mark.asyncio
    async def test_get_single_syn_form_with_refcount(self):
        syn_tufo = Tufo(logging.getLogger(__name__))

        adjacent_ref_count = 2
        result = await syn_tufo.get_single('inet:ipv4=56.56.56.56',
                                           None,
                                           adjacent_ref_count,
                                           (('inet:url', 'http://www.example.com/index.html'),
                                            ('inet:dns:a', '(www.example.com, 56.56.56.56)'),
                                           ))
        assert result
        assert {'guid', 'type', 'property', 'secondary_property', 'adjacent_nodes'} <= result.keys()
        assert result['type'] == 'inet:ipv4'
        assert result['property'] == '56.56.56.56'
        assert len(result['adjacent_nodes']) == 2
        assert result['adjacent_nodes'][0]['type'] == 'inet:dns:a'
        assert result['adjacent_nodes'][0]['property'] == '(www.example.com, 56.56.56.56)'
        assert result['adjacent_nodes'][1]['type'] == 'inet:fqdn'
        assert result['adjacent_nodes'][1]['property'] == 'www.example.com'

    @pytest.mark.asyncio
    async def test_get_single_filebytes_reference(self):
        """This test checks that file:bytes edge:refs are working correctly. With a'count==1' or a single 'out' name,
         then any indicators that are present should be returned in result-set."""
        logger = logging.getLogger(__name__)
        syn_tufo = Tufo(logger)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            syn_tufo = Tufo(logger, cortex_db)
            fb_guids = await self.create_file_bytes_xrefs(cortex_db, logger)
            await self.create_file_bytes_urlfile(cortex_db, logger, fb_guids)

            adjacent_ref_count = 2
            result = await syn_tufo.get_single(f'file:bytes={fb_guids[1]}', None, adjacent_ref_count)
            assert result
            types_found = [node['type'] for node in result['adjacent_nodes']]
            assert types_found == ['hash:md5', 'hash:sha1', 'hash:sha256', 'hash:sha512', 'file:base',
                                   'file:mime', 'file:ismime', 'inet:urlfile', 'inet:url', 'inet:url', 'inet:fqdn']

            adjacent_ref_names = ['out']
            result = await syn_tufo.get_single(f'file:bytes={fb_guids[1]}', adjacent_ref_names, 0)
            assert result
            types_found = [node['type'] for node in result['adjacent_nodes']]
            assert types_found == ['hash:md5', 'hash:sha1', 'hash:sha256', 'hash:sha512', 'file:base', 'file:mime',
                                   'inet:url', 'inet:fqdn']

    @pytest.mark.asyncio
    async def test_get_single_filebytes_enrichment(self):
        """This test emulates the file:bytes VT enrichment where an exception was found while recursively
         walking file:base with Unicode file"""
        logger = logging.getLogger(__name__)
        syn_tufo = Tufo(logger)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            syn_tufo = Tufo(logger, cortex_db)
            fb_guids = await self.create_file_bytes_xrefs(cortex_db, logger, filename='Комерческое предложение.doc.vbs')

            adjacent_ref_names = ['out', 'out']
            result = await syn_tufo.get_single(f'file:bytes:sha1={fb_guids[2]}', adjacent_ref_names, 0)
            assert result
            types_found = [node['type'] for node in result['adjacent_nodes']]
            assert types_found == ['hash:md5', 'hash:sha1', 'hash:sha256', 'hash:sha512', 'file:base', 'file:mime', 'inet:url', 'inet:fqdn']

    @pytest.mark.asyncio
    async def test_get_single_syn_form_no_referenced_nodes(self):
        """This test ensures that a node with no references always returns an empty list 'adjacent_nodes' key."""
        syn_tufo = Tufo(logging.getLogger(__name__))

        adjacent_ref_count = 1
        result = await syn_tufo.get_single('it:dev:mutex=Mutex_Check',
                                           None,
                                           adjacent_ref_count,
                                           (('it:dev:mutex', 'Mutex_Check'),
                                           ))
        assert result
        assert {'guid', 'type', 'property', 'secondary_property', 'adjacent_nodes'} <= result.keys()
        assert result['adjacent_nodes'] == []

    @pytest.mark.asyncio
    async def test_get_indicator_filebytes(self):
        """This test checks that a reverse relationship is traversed, so FQDN -> file:bytes node is returned"""
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            syn_tufo = Tufo(logger, cortex_db)
            fb_guids = await self.add_filebytes(cortex_db, 'myreport.pdf')
            guid2 = await self.add_fqdn(cortex_db, 'www.example.com')
            req = {
                'parent': {'type': 'file:bytes', 'property': fb_guids[1]},
                'child': {'type': 'inet:fqdn', 'property': guid2[1]},
            }
            req = CreateCompositeNode(logger, req, cortex_db)
            results = await req.run()

            adjacent_ref_names = ['in']
            result = await syn_tufo.get_single('inet:fqdn=www.example.com', adjacent_ref_names, 0)
            assert result
            assert result['adjacent_nodes'][0]['type'] == 'file:bytes'

            adjacent_ref_count = 1
            result = await syn_tufo.get_single('inet:fqdn=www.example.com', None, adjacent_ref_count)
            assert result
            assert {'guid', 'type', 'property', 'secondary_property', 'adjacent_nodes'} <= result.keys()
            assert len(result['adjacent_nodes']) == 2
            assert result['adjacent_nodes'][0]['type'] == 'inet:fqdn'
            assert result['adjacent_nodes'][0]['property'] == 'example.com'
            assert result['adjacent_nodes'][1]['type'] == 'file:bytes'

    @pytest.mark.asyncio
    async def test_get_single_syn_form_with_refnames(self):
        syn_tufo = Tufo(logging.getLogger(__name__))

        adjacent_ref_count = 0
        adjacent_ref_names = ['out', 'any']
        result = await syn_tufo.get_single('inet:url=http://www.example.com/index.html',
                                           adjacent_ref_names,
                                           adjacent_ref_count,
                                           (('inet:url', 'http://www.example.com/index.html'),
                                            ('inet:dns:a', '(www.example.com,56.56.56.56)'),
                                           ))
        assert result
        assert {'guid', 'type', 'property', 'secondary_property', 'adjacent_nodes'} <= result.keys()
        assert result['type'] == 'inet:url'
        assert result['property'] == 'http://www.example.com/index.html'
        assert len(result['adjacent_nodes']) == 3
        assert result['adjacent_nodes'][0]['type'] == 'inet:fqdn'
        assert result['adjacent_nodes'][0]['property'] == 'www.example.com'

    @pytest.mark.asyncio
    async def test_get_single_syn_form_with_bad_refnames(self):
        syn_tufo = Tufo(logging.getLogger(__name__))

        adjacent_ref_count = 0
        adjacent_ref_names = ['out', 'bad']
        with pytest.raises(errors.ParameterError):
            result = await syn_tufo.get_single('inet:url=http://www.example.com/index.html',
                                               adjacent_ref_names,
                                               adjacent_ref_count,
                                               (('inet:url', 'http://www.example.com/index.html'),
                                                ('inet:dns:a', '(www.example.com,56.56.56.56)'),
                                               ))

    @pytest.mark.asyncio
    async def test_get_single_guid_form(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__))

        async with cortex_db:
            syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
            guids_list = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                       (('inet:ipv4', '9.9.9.9'),
                                                       ))
            adjacent_ref_count = 0
            result = await syn_tufo.get_single(guids_list[0], None, adjacent_ref_count)

        assert result
        assert {'guid', 'type', 'property', 'secondary_property'} <= result.keys()
        assert result['type'] == 'inet:ipv4'

    @pytest.mark.asyncio
    async def test_add_single_node_ipv4(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))
            assert len(guids) == 1
            result = await syn_tufo.add_single_node('inet:ipv4=23.23.23.23',
                                                    ['int.tag1'],
                                                    {'type': 'internal',
                                                    'asn': 1000,
                                                    })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['secondary_property']['asn'] == 1000
            assert result['data']['secondary_property']['type'] == 'unicast'

    @pytest.mark.asyncio
    async def test_tranco(self):
        t_rank = TrancoRanked(logging.getLogger(__name__))
        result = t_rank.is_ranked('google.com')
        assert result

    @pytest.mark.asyncio
    async def test_add_single_node_fqdn_tranco(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'omit.tranco'),
                                                   ))
            assert len(guids) == 1
            result = await syn_tufo.add_single_node('inet:fqdn=google.com',
                                                    [],
                                                    {},
                                                    check_tranco_list=True)
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['secondary_property']['host'] == 'google'
            assert result['data']['secondary_property']['domain'] == 'com'

    @pytest.mark.asyncio
    async def test_add_single_node_url_tranco(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'omit.tranco'),
                                                   ))
            assert len(guids) == 1
            result = await syn_tufo.add_single_node('inet:url=http://www.example.com/index.html',
                                                    [],
                                                    {},
                                                    check_tranco_list=True)
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['secondary_property']['fqdn'] == 'www.example.com'
            assert result['data']['secondary_property']['proto'] == 'http'

    @pytest.mark.asyncio
    async def test_upsert_single_node_ipv4(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                   ('inet:ipv4', '23.23.23.23')
                                                  ))
            assert len(guids) == 2
            result = await syn_tufo.add_single_node('inet:ipv4=23.23.23.23',
                                                    ['int.tag1'],
                                                    {'type': 'internal',
                                                     'asn': 1000,
                                                    },
                                                    missing_exception=False)
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['secondary_property']['asn'] == 1000
            assert result['data']['secondary_property']['type'] == 'unicast'


    @pytest.mark.asyncio
    async def test_add_single_node_whois_email(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))
            assert len(guids) == 1
            result = await syn_tufo.add_single_node('inet:whois:email=(malware.org, abuse@dontcontactme.info)',
                                                    ['int.tag1'],
                                                    {})
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['type'] == 'inet:whois:email'

    @pytest.mark.asyncio
    async def test_add_single_node_whois_email_raw(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))
            assert len(guids) == 1
            result = await syn_tufo.add_single_raw('inet:whois:email', ('malware.org', 'abuse@dontcontactme.info'),
                                                    ['int.tag1'],
                                                    {})
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['type'] == 'inet:whois:email'

    @pytest.mark.asyncio
    async def test_add_single_node_text_with_newline(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))
            assert len(guids) == 1
            result = await syn_tufo.add_single_raw('inet:whois:rec', ('expel.io', '2018/12/12'),
                                                   ['int.tag1=(20181001,20191029000429)'],
                                                   {'created': '2016/07/11T16:24:41', 'expires': '2024/07/11T16:24:41',
                                                    'registrant': 'c/o whoisproxy.com',
                                                    'registrar': 'Key-Systems GmbH',
                                                    'text': 'Domain Name: EXPEL.IO\n'
                                                            'Registry Domain ID: D503300000040400426-LRMS\n'
                                                            'Registrar WHOIS Server: whois.rrpproxy.net\n'
                                                            'Registrar URL: http://www.key-systems.net\n'
                                                            'Updated Date: 2018-06-11T21:58:39Z\n'
                                                            'Creation Date: 2016-07-11T16:24:41Z\n'
                                                            'Registry Expiry Date: 2024-07-11T'
                                                   })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['type'] == 'inet:whois:rec'
            assert result['data']['secondary_property']['text'].startswith('domain name: expel.io\nregistry domain id: d503300000040400426-lrms')
            assert len(result['data']['secondary_property'].keys()) == 7

    @pytest.mark.asyncio
    async def test_add_single_node_invalid_ipv4_prop_value(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            with pytest.raises(errors.InvalidSynapseProperty) as err:
                result = await syn_tufo.add_single_node('inet:ipv4=23.23.23.23',
                                                        [],
                                                        {'asn': 'invalid_asn',
                                                        })

    @pytest.mark.asyncio
    async def test_add_invalid_dev_it_str(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            with pytest.raises(errors.ParameterError):
                result = await syn_tufo.add_single_node('it:dev:str=quote(")',
                                                        [],
                                                        {})

    @pytest.mark.asyncio
    async def test_add_file_bytes_filename_with_spaces(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))


            assert len(guids) == 1
            result = await syn_tufo.add_single_node('file:bytes=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                                    ['int.tag1'],
                                                    {'name': 'Big "Earthquake" Triggered Today.pdf',
                                                     'mime': 'application/octet-stream',
                                                    })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['secondary_property']['name'] == 'big "earthquake" triggered today.pdf'
            assert result['data']['secondary_property']['mime'] == 'application/octet-stream'

    @pytest.mark.asyncio
    async def test_add_file_bytes_filename_with_parenthesis(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))


            assert len(guids) == 1
            result = await syn_tufo.add_single_node('file:bytes=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                                    ['int.tag1'],
                                                    {'mime:pe:compiled': 1431312336000,
                                                     'name': 'Hello(World).pdf',
                                                     'mime': 'application/pdf',
                                                     'size': 1000,
                                                     '.seen': 'now',
                                                     'mime:pe:imphash': '635a04a01b6dd4b1ee8101fb427b26c2',
                                                    })
            assert 'data' in result
            assert isinstance(result['data'], dict)
            assert {'type', 'property', 'guid'} <= result['data'].keys()
            assert result['data']['secondary_property']['name'] == 'hello(world).pdf'
            assert result['data']['secondary_property']['mime'] == 'application/pdf'
            assert result['data']['secondary_property']['size'] == 1000
            assert result['data']['secondary_property']['mime:pe:compiled'] == 1431312336000

    @pytest.mark.asyncio
    async def test_add_invalid_url(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            with pytest.raises(errors.InvalidSynapseProperty):
                result = await syn_tufo.add_single_node('inet:url=http:/www.evilempire.biz/c2c.php',
                                                        [],
                                                        {})

    @pytest.mark.asyncio
    async def test_add_url_double_backslash(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        the_str_url = 'inet:url=http://www.evilempire.biz/c2c.php\\,pattern'
        async with cortex_db:
            add_result = await syn_tufo.add_single_node(the_str_url, [], {})
            assert add_result['data']['type'] == 'inet:url'
            assert add_result['data']['property'].index('\\,pattern') >= len('http://www.evilempire.biz/c2c.php')
            get_result = await syn_tufo.get_single(the_str_url, None, 0)
            assert get_result
            assert get_result['property'].index('\\,pattern') >= len('http://www.evilempire.biz/c2c.php')

    @pytest.mark.asyncio
    async def test_add_it_dev_str(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        the_str = qsv.parse('it:dev:str', 'c:\\windows\\system32\\')
        async with cortex_db:
            add_result = await syn_tufo.add_single_node(the_str, [], {})
            assert add_result['data']['type'] == 'it:dev:str'
            assert add_result['data']['property'] == 'c:\\windows\\system32\\'
            get_result = await syn_tufo.get_single(the_str, None, 0)
            assert get_result
            assert get_result['property'] == 'c:\\windows\\system32\\'

    @pytest.mark.asyncio
    async def test_add_file_bytes_bad_property(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)

        async with cortex_db:
            guids = await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                                  (('syn:tag', 'int.tag1'),
                                                  ))

            assert len(guids) == 1
            with pytest.raises(errors.InvalidSynapseProperty):
                result = await syn_tufo.add_single_node('file:bytes=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                                        ['int.tag1'],
                                                        {'badprop': '9a8517291d4d00a4dbcfb8e5c45ab84749234ae8',
                                                         'name': 'MyApp.exe',
                                                        })
