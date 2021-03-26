import pytest
import asyncio
import logging
from helpers.http_errors import ParameterError, ResourceMissingError, ResourceExistsError, HttpError
from helpers.indicator_validate import IndicatorValidate
import helpers.quoted_storm_value as qsv
from helpers.synapse_010_format import (sf_get_guid, sf_was_added, sf_get_first_node, sf_has_property,
                                        sf_get_form_name, sf_get_form_value)
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.userctx import OperationSource, UserContext
from libs.cortex_db import CortexDb, read_async
from libs.synapse_models.composite_nodes import CandidateCompositeNodes, CreateCompositeNode

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

def return_user_request():
    return UserContext(100, 'george@example.com', '0AXB9V5GUdg8m4om10jCMeUr', OperationSource.passive_total)

@pytest.mark.usefixtures('setup_config')
class TestCandidateCompositeNodes():
    def test_ipv4_fqdn(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'inet:ipv4', 'property': '9.9.9.9'},
            {'type': 'inet:fqdn', 'property': 'www.example.com'},
            {'type': 'inet:url', 'property': 'https://www.bunny.com'},
            {'type': 'inet:ipv4', 'property': '9.9.9.9'},
            {'type': 'inet:ipv4', 'property': '10.10.10.10'},
            {'type': 'inet:fqdn', 'property': 'bunny.com'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()
        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 4
        data = results['data'][0]
        assert data['parent']['type'] == 'inet:fqdn'
        assert data['parent']['property'] == 'bunny.com'
        assert data['child']['type'] == 'inet:ipv4'
        assert data['child']['property'] == '10.10.10.10'
        assert data['new_type'] == 'inet:dns:a'
        assert 'DNS' in data['desc']
        for r in results['data']:
            assert r['new_type'] == 'inet:dns:a'

    def test_urlfile_file(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:b5a158091ed42129a49425ee1b006105'},
            {'type': 'inet:url', 'property': 'https://www.malware-report.com'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 3
        data = results['data'][2]
        assert data['parent']['type'] == 'inet:url'
        assert data['parent']['property'] == 'https://www.malware-report.com'
        assert data['child']['type'] == 'file:bytes'
        assert data['child']['property'] == 'guid:b5a158091ed42129a49425ee1b006105'
        assert data['new_type'] == 'inet:urlfile'

    def test_ou_has_file(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'ou:org', 'property': '83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'file:bytes', 'property': 'guid:b5a158091ed42129a49425ee1b006105'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 1
        data = results['data'][0]
        assert data['parent']['type'] == 'ou:org'
        assert data['parent']['property'] == '83ac4984d21d7e8812338944f1b8a3b2'
        assert data['child']['type'] == 'file:bytes'
        assert data['child']['property'] == 'guid:b5a158091ed42129a49425ee1b006105'
        assert data['new_type'] == 'ou:org:has'

    def test_edgeref(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'inet:ipv4', 'property': '23.23.23.23'},
            {'type': 'inet:fqdn', 'property': 'www.example.com'},
            {'type': 'inet:url', 'property': 'https://www.bunny.com'},
            {'type': 'it:dev:regkey', 'property': '/yyyy/twitter'},
            {'type': 'it:dev:regval', 'property': '09c3239078c6a0fe11982fc37266c0e6'},
            {'type': 'inet:passwd', 'property': 'asdfghj^@#'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 13
        data = results['data'][0]
        assert data['parent']['type'] == 'file:bytes'
        assert data['parent']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b2'
        assert data['child']['type'] == 'inet:url'
        assert data['child']['property'] == 'https://www.bunny.com'
        assert data['new_type'] == 'edge:refs'
        found_regkey = False
        found_regval = False
        for node in results['data']:
            if node == {'parent': {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
                        'child': {'type': 'it:dev:regkey', 'property': '/yyyy/twitter'},
                        'desc': 'A file bytes to registry key',
                        'new_type': 'edge:refs'}:
                found_regkey = True
            elif node == {'parent': {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
                          'child': {'type': 'it:dev:regval', 'property': '09c3239078c6a0fe11982fc37266c0e6'},
                          'desc': 'A file bytes to registry value',
                          'new_type': 'edge:refs'}:
                found_regval = True
        assert found_regkey
        assert found_regval

    def test_edgeref_url_ipv4_address(self):
        """This test case evaluates how the authority field in URL is processed as either an
           FQDN and IP address.
         """
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'inet:url', 'property': 'https://www.bunny.com/index.php'},
            {'type': 'inet:url', 'property': 'https://1.1.1.1:80/index.php'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 7
        expected_results = (('inet:url', 'https://1.1.1.1:80/index.php'),
                            ('inet:url', 'https://www.bunny.com/index.php'),
                            ('inet:ipv4', '1.1.1.1'),
                            ('inet:fqdn', 'bunny.com'),
                            ('file:bytes', 'guid:83ac4984d21d7e8812338944f1b8a3b2'),
                            ('inet:ipv4', '1.1.1.1'),
                            ('file:bytes', 'guid:83ac4984d21d7e8812338944f1b8a3b2'))
        results_index = 0
        for item in results['data']:
            assert item['child']['type'] == expected_results[results_index][0]
            assert item['child']['property'] == expected_results[results_index][1]
            results_index += 1

    def test_edgeref_url_ipv6_address(self):
        """This test case evaluates how the authority field in URL is processed as either an
           FQDN and IP address.
         """
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'inet:url', 'property': 'https://www.bunny.com/index.php'},
            {'type': 'inet:url', 'property': 'https://[fe80::282f:cc41:15f0:f915]:80/index.php'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 6
        expected_results = (('inet:url', 'https://[fe80::282f:cc41:15f0:f915]:80/index.php'),
                            ('inet:url', 'https://www.bunny.com/index.php'),
                            ('inet:ipv6', 'fe80::282f:cc41:15f0:f915'),
                            ('inet:fqdn', 'bunny.com'),
                            ('file:bytes', 'guid:83ac4984d21d7e8812338944f1b8a3b2'),
                            ('file:bytes', 'guid:83ac4984d21d7e8812338944f1b8a3b2'),
                            )
        results_index = 0
        for item in results['data']:
            assert item['child']['type'] == expected_results[results_index][0]
            assert item['child']['property'] == expected_results[results_index][1]
            results_index += 1

    def test_exec_regval(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'it:dev:regval', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b3'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 4
        data = results['data'][1]
        assert data['parent']['type'] == 'file:bytes'
        assert data['parent']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b2'
        assert data['child']['type'] == 'it:dev:regval(get)'
        assert data['child']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b3'
        assert data['new_type'] == 'it:exec:reg:get'

    def test_exec_mutex(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'it:dev:mutex', 'property': 'abc'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 1
        data = results['data'][0]
        assert data['parent']['type'] == 'file:bytes'
        assert data['parent']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b2'
        assert data['child']['type'] == 'it:dev:mutex'
        assert data['child']['property'] == 'abc'
        assert data['new_type'] == 'it:exec:mutex'

    def test_exec_mutex(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'it:dev:pipe', 'property': 'abc'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 1
        data = results['data'][0]
        assert data['parent']['type'] == 'file:bytes'
        assert data['parent']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b2'
        assert data['child']['type'] == 'it:dev:pipe'
        assert data['child']['property'] == 'abc'
        assert data['new_type'] == 'it:exec:pipe'

    def test_exec_file(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b3'},
        ]
        cnodes = CandidateCompositeNodes(logger, cnodes)
        results = cnodes.run()
        assert isinstance(results, dict)
        assert {'status', 'msg', 'data'} <= results.keys()

        assert isinstance(results['data'][0], dict)
        assert len(results['data']) == 5
        data = results['data'][0]
        assert data['parent']['type'] == 'file:bytes'
        assert data['parent']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b2'
        assert data['child']['type'] == 'file:bytes(add)'
        assert data['child']['property'] == 'guid:83ac4984d21d7e8812338944f1b8a3b3'

        expected_forms = ('it:exec:file:add', 'it:exec:file:del', 'it:exec:file:read',
                          'it:exec:file:write', 'file:subfile')
        form_index = 0
        for item in results['data']:
            assert item['new_type'] == expected_forms[form_index]
            form_index += 1

    def test_exec_file_too_many(self):
        logger = logging.getLogger(__name__)
        cnodes = [
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b2'},
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b3'},
            {'type': 'file:bytes', 'property': 'guid:83ac4984d21d7e8812338944f1b8a3b4'},
        ]
        with pytest.raises(ParameterError):
            cnodes = CandidateCompositeNodes(logger, cnodes)
            results = cnodes.run()

@pytest.mark.usefixtures("setup_config")
class TestCreateInvalidCompositeNodes:
    """This class test non-async functions"""
    def test_message_invalid_type(self):
        cnode = 'hello'
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

    def test_message_missing_parent(self):
        cnode = {
            'bad': {'type': 'inet:fqdn', 'property': 'www.bunny.com'},
            'child': {'type': 'inet:ipv4', 'property': '23.23.23.23'},
        }
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

    def test_message_missing_child(self):
        cnode = {
            'parent': {'type': 'inet:fqdn', 'property': 'www.bunny.com'},
            'bad': {'type': 'inet:ipv4', 'property': '23.23.23.23'},
        }
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

    def test_message_missing_parent_type(self):
        cnode = {
            'parent': {'bad': 'inet:fqdn', 'property': 'www.bunny.com'},
            'child': {'type': 'inet:ipv4', 'property': '23.23.23.23'},
        }
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

    def test_message_missing_parent_property(self):
        cnode = {
            'parent': {'type': 'inet:fqdn', 'bad': 'www.bunny.com'},
            'child': {'type': 'inet:ipv4', 'property': '23.23.23.23'},
        }
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

    def test_message_missing_child_type(self):
        cnode = {
            'parent': {'type': 'inet:fqdn', 'property': 'www.bunny.com'},
            'child': {'bad': 'inet:ipv4', 'property': '23.23.23.23'},
        }
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

    def test_message_missing_child_property(self):
        cnode = {
            'parent': {'type': 'inet:fqdn', 'property': 'www.bunny.com'},
            'child': {'type': 'inet:ipv4', 'bad': '23.23.23.23'},
        }
        logger = logging.getLogger(__name__)
        with pytest.raises(ParameterError):
            cnodes = CreateCompositeNode(logger, cnode)

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestCreateCompositeNodes():

    async def _add_filebytes(self, cortex_db, guid, name):
        syn_query = '[ file:bytes={} :name={} :mime=application/pdf ]'.format(guid, name)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def _add_url(self, cortex_db, url):
        syn_query = '[ inet:url="{}" ]'.format(url)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), url)
        return results

    async def _add_fqdn(self, cortex_db, fqdn):
        syn_query = '[ inet:fqdn={} ]'.format(fqdn)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), fqdn)
        return results

    async def _add_hash(self, cortex_db, hash):
        iv = IndicatorValidate()
        form = iv.match_form(hash)
        syn_query = '[ {}={} ]'.format(form, hash)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), hash)
        return results

    async def _add_ou_org(self, cortex_db, name, alias):
        syn_query = '[ ou:org=72ee52c55ff697efef82a547a3538a84 :name="{}" :alias={} :url=http://www.example.com ]'.format(name, alias)
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def _add_regval(self, cortex_db, guid, value):
        syn_query = '[ {} {} ]'.format(qsv.parse('it:dev:regval', guid), qsv.parse(':key', value))
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def _add_regval2(self, cortex_db, value):
        syn_query = '[ it:dev:regval="*" {} ]'.format(qsv.parse(':key', value))
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def _add_regkey(self, cortex_db, value):
        syn_query = '[ {} ]'.format(qsv.parse('it:dev:regkey', value))
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def _add_mutex(self, cortex_db, value):
        syn_query = '[ {} ]'.format(qsv.parse('it:dev:mutex', value))
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def _add_devstr(self, cortex_db, value):
        syn_query = '[ {} ]'.format(qsv.parse('it:dev:str', value))
        ask_results = await read_async(None, cortex_db.conn(), syn_query)
        created_rec = sf_get_first_node(ask_results)
        assert created_rec
        results = (sf_get_guid(created_rec), sf_get_form_value(created_rec))
        return results

    async def test_dns_a(self):
        logger = logging.getLogger(__name__)
        cnode = {
            'parent': {'type': 'inet:fqdn', 'property': 'www.bunny.com'},
            'child': {'type': 'inet:ipv4', 'property': '23.23.23.23'},
        }
        cnodes = CreateCompositeNode(logger, cnode, userctx=return_user_request())
        results = await cnodes.run()
        assert {'status', 'msg', 'data'} <= results.keys()
        assert results['data']['property'] == '(www.bunny.com, 23.23.23.23)'
        assert results['data']['secondary_property']['fqdn'] == 'www.bunny.com'
        assert results['data']['secondary_property']['ipv4'] == '23.23.23.23'

    async def test_dns_a_duplicate(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:

            cnode = {
                'parent': {'type': 'inet:fqdn', 'property': 'www.bunny.com'},
                'child': {'type': 'inet:ipv4', 'property': '23.23.23.23'},
            }
            cnodes = CreateCompositeNode(logger, cnode, cortex_db)
            results = await cnodes.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['property'] == '(www.bunny.com, 23.23.23.23)'
            assert results['data']['secondary_property']['fqdn'] == 'www.bunny.com'
            assert results['data']['secondary_property']['ipv4'] == '23.23.23.23'

            with pytest.raises(ResourceExistsError):
                results = await cnodes.run()

    async def test_urlfile(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_url(cortex_db, 'https://twitter.com/oguzpamuk/status/1160905143593910272?s=20')
            cnode_req = {
                'parent': {'type': 'inet:url', 'property': guid2[1]},
                'child': {'type': 'file:bytes', 'property': guid[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['secondary_property']['url']\
                   == 'https://twitter.com/oguzpamuk/status/1160905143593910272?s=20'
            assert results['data']['secondary_property']['file']\
                   == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'

    async def test_urlfile_bad_guid(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_url(cortex_db, 'https://www.malware-reports.com/myreport.pdf')
            cnode_req = {
                'parent': {'type': 'inet:url', 'property': guid2[1]},
                'child': {'type': 'file:bytes', 'property': 'guid:e7ffc308789389cdbf5bb4a1b83e4141'},
            }
            with pytest.raises(ResourceMissingError):
                req = CreateCompositeNode(logger, cnode_req, cortex_db)
                results = await req.run()

    async def test_ou_org_has_filebytes(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_ou_org(cortex_db, 'Example Widget Corp', 'EWC')
            cnode_req = {
                'parent': {'type': 'ou:org', 'property': guid2[1]},
                'child': {'type': 'file:bytes', 'property': guid[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['secondary_property']['org'] == guid2[1]
            assert results['data']['secondary_property']['node'] == ('file:bytes', guid[1])
            assert results['data']['secondary_property']['node:form'] == 'file:bytes'

    async def test_file_bytes_xref(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        regkey = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\WinIdentifiers'
        child_indicators = ((self._add_fqdn, 'inet:fqdn', 'www.example.com'),
                            (self._add_devstr, 'it:dev:str', 'file"evil"with(string)'),
                            (self._add_url, 'inet:url', 'https://www.dropbox.com/upgrade?oqa=upeao'),
                            (self._add_regkey, 'it:dev:regkey', regkey),
                            (self._add_regval2, 'it:dev:regval', regkey),
                            )

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            for test_ind in child_indicators:
                guid2 = await test_ind[0](cortex_db, test_ind[2])
                cnode_req = {
                    'parent': {'type': 'file:bytes', 'property': guid[1]},
                    'child': {'type': test_ind[1], 'property': guid2[1]},
                }

                req = CreateCompositeNode(logger, cnode_req, cortex_db)
                results = await req.run()
                assert {'status', 'msg', 'data'} <= results.keys()
                assert results['data']['secondary_property']['n1'] == ('file:bytes', guid[1])
                if results['data']['secondary_property']['n2'][0] == 'it:dev:regval':
                    assert results['data']['secondary_property']['n2'][0] == 'it:dev:regval'
                    assert len(results['data']['secondary_property']['n2'][1]) == 32
                else:
                    assert results['data']['secondary_property']['n2'] == (test_ind[1], test_ind[2])
            # Verify that child nodes were created
            syn_query = 'file:bytes=%s -> edge:refs -> *' % guid[1]
            check_result = await read_async(None, cortex_db.conn(), syn_query)
            assert len(check_result) == len(child_indicators)

    async def test_file_bytes_xref_duplicate(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_url(cortex_db, 'https://www.dropbox.com/upgrade?oqa=upeao')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'inet:url', 'property': guid2[1]},
            }
            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['secondary_property']['n1'] == ('file:bytes', guid[1])
            assert results['data']['secondary_property']['n2'] == ('inet:url', guid2[1])

            with pytest.raises(ResourceExistsError) as err:
                results = await req.run()
            assert str(err.value).index('https://www.dropbox.com/upgrade?oqa=upeao') >= 0

    async def test_file_bytes_xref_hash(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            for hash in (('da498a80ff5a96d69dd86b729c719331', 'hash:md5'),
                         ('9a07ebd68a70618b8b47f98d0dd3881c3035e7ff', 'hash:sha1'),
                         ('43efc9cc0f306b9c9d81d33dc1701049749d696183eaf051cf90d92609a09d9b', 'hash:sha256'),
                         ('1b7d6e3ba7143e2834d3dd89105bba3e0ebb46838ba955e4a2a145e422426515d89e6834aedeef46f44b367d65405c52a542ce88afa3066e4586521b09860fb8',
                              'hash:sha512')):
                guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
                guid2 = await self._add_hash(cortex_db, hash[0])
                cnode_req = {
                    'parent': {'type': 'file:bytes', 'property': guid[1]},
                    'child': {'type': hash[1], 'property': guid2[1]},
                }

                req = CreateCompositeNode(logger, cnode_req, cortex_db)
                results = await req.run()
                assert {'status', 'msg', 'data'} <= results.keys()
                assert results['data']['secondary_property']['n1'] == ('file:bytes', guid[1])
                assert results['data']['secondary_property']['n2'] == (hash[1], guid2[1])

    async def test_exec_regval(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            regkey = 'hklm\\software\\microsoft\\wauqysvc: "wlansvc"'
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_regval(cortex_db, '83ac4984d21d7e8812338944f1b8a3b3', regkey)
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'it:dev:regval(set)', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'it:exec:reg:set'
            assert results['data']['secondary_property']['exe'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['reg'] == guid2[1]

    async def test_exec_regval_duplicate(self):
        """Test creating duplicate file:bytes <> it:dev:regval node"""
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_regval(cortex_db, '83ac4984d21d7e8812338944f1b8a3b3', 'hklm\\software\\microsoft\\wauqysvc: "wlansvc"')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'it:dev:regval(set)', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'it:exec:reg:set'
            assert results['data']['secondary_property']['exe'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['reg'] == guid2[1]

            with pytest.raises(ResourceExistsError):
                results = await req.run()

    async def test_exec_mutex(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_mutex(cortex_db, 'mutex abc')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'it:dev:mutex', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'it:exec:mutex'
            assert results['data']['secondary_property']['exe'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['name'] == guid2[1]

    async def test_exec_mutex_duplicate(self):
        """Test creating duplicate file:bytes <> it:dev:mutex node"""
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'myreport.pdf')
            guid2 = await self._add_mutex(cortex_db, 'mutex abc')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'it:dev:mutex', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'it:exec:mutex'
            assert results['data']['secondary_property']['exe'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['name'] == guid2[1]

            with pytest.raises(ResourceExistsError):
                results = await req.run()

    async def test_exec_file(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'evil.exe')
            guid2 = await self._add_filebytes(cortex_db, 'guid:83ac4984d21d7e8812338944f1b8a3b3', 'crack.dll')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'file:bytes(add)', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'it:exec:file:add'
            assert results['data']['secondary_property']['exe'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['file'] == 'guid:83ac4984d21d7e8812338944f1b8a3b3'

    async def test_exec_file_bad_child_guid(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'evil.exe')
            guid2 = await self._add_filebytes(cortex_db, 'guid:83ac4984d21d7e8812338944f1b8a3b3', 'crack.dll')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': 'guid:e7ffc308789389cdbf5bb4a1b83e4140'},
                'child': {'type': 'file:bytes(add)', 'property': 'guid:X3ac4984d21d7e8812338944f1b8a3b2'},
            }

            with pytest.raises(ParameterError):
                req = CreateCompositeNode(logger, cnode_req, cortex_db)
                results = await req.run()

    async def test_exec_file_bad_parent_guid(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'evil.exe')
            guid2 = await self._add_filebytes(cortex_db, 'guid:83ac4984d21d7e8812338944f1b8a3b3', 'crack.dll')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': 'guid:X3ac4984d21d7e8812338944f1b8a3b2'},
                'child': {'type': 'file:bytes(add)', 'property': 'guid:e7ffc308789389cdbf5bb4a1b83e4140'},
            }

            with pytest.raises(ParameterError):
                req = CreateCompositeNode(logger, cnode_req, cortex_db)
                results = await req.run()

    async def test_exec_file_duplicate(self):
        """This test case verifies that duplicate it:exec:file:add logic triggers an exception."""
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'evil.exe')
            guid2 = await self._add_filebytes(cortex_db, 'guid:83ac4984d21d7e8812338944f1b8a3b3', 'crack.dll')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'file:bytes(add)', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'it:exec:file:add'
            assert results['data']['secondary_property']['exe'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['file'] == 'guid:83ac4984d21d7e8812338944f1b8a3b3'

            with pytest.raises(ResourceExistsError):
                results = await req.run()

    async def test_filebytes_subfile(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'evil.zip')
            guid2 = await self._add_filebytes(cortex_db, 'guid:83ac4984d21d7e8812338944f1b8a3b3', 'crack.dll')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'file:bytes(child)', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'file:subfile'
            assert results['data']['property'] == '(guid:e7ffc308789389cdbf5bb4a1b83e4140, guid:83ac4984d21d7e8812338944f1b8a3b3)'
            assert results['data']['secondary_property']['parent'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['child'] == 'guid:83ac4984d21d7e8812338944f1b8a3b3'

    async def test_filebytes_subfile_duplicate(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)

        async with cortex_db:
            guid = await self._add_filebytes(cortex_db, 'guid:e7ffc308789389cdbf5bb4a1b83e4140', 'evil.zip')
            guid2 = await self._add_filebytes(cortex_db, 'guid:83ac4984d21d7e8812338944f1b8a3b3', 'crack.dll')
            cnode_req = {
                'parent': {'type': 'file:bytes', 'property': guid[1]},
                'child': {'type': 'file:bytes(child)', 'property': guid2[1]},
            }

            req = CreateCompositeNode(logger, cnode_req, cortex_db)
            results = await req.run()
            assert {'status', 'msg', 'data'} <= results.keys()
            assert results['data']['type'] == 'file:subfile'
            assert results['data']['property'] == '(guid:e7ffc308789389cdbf5bb4a1b83e4140, guid:83ac4984d21d7e8812338944f1b8a3b3)'
            assert results['data']['secondary_property']['parent'] == 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
            assert results['data']['secondary_property']['child'] == 'guid:83ac4984d21d7e8812338944f1b8a3b3'

            with pytest.raises(ResourceExistsError):
                results = await req.run()
