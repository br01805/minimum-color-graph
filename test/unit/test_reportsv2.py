import pytest
import logging
import time
from libs.reports.models import Models
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async
from libs.reports.transforms2 import ReportFactory
from libs.db_node_history import DbNodeHistory, ArangoConfig
from libs.userctx import OperationSource, UserContext
from libs.synapse_nodes import Tufo
from test.unit.report_mocks.malware_mock import MalwareReports
from libs.reports.stix.create_stix_report import StixBundle
from helpers.http_errors import StixTranslationError

syn_mods = ['models.media.MediaModule', 'models.files.FileModule']

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True


async def add_nodes(cortex_db, ioc_type, max_num, f_guid):
    n_list = []
    current_time = time.strftime('%Y-%m-%dZ', time.gmtime())
    d_tags = ['mal.wannacry', 'pwn.test',
              'code.test', 'tgt.test',
              'bookmark.test', 'review.test',
              'int.test', 'thr.test',
              'bhv.test', 'trend.test']
    op_type = {
        'domain': add_domain_nodes,
        'hash': add_hash_nodes,
        'ip': add_ip_nodes,
    }
    n_list = await op_type[ioc_type](cortex_db, max_num, f_guid)
    return (n_list, current_time)


async def add_report(cortex_db, group, max_num, html=False):
    r_list = []
    def extract_id(resp):
        n_property = ''
        for node in resp:
            if node[0] == 'node':
                n_property = node[1][0][1]
        return n_property

    async def create_news(f_id, s_id, num, cortex_db, html):
        m_query = '[media:news="*" '
        m_query += f':title="{group} title {num}" '
        m_query += f':summary="{group} summary" ' if not html else ' '
        m_query += f':file={f_id} :source={s_id} '
        m_query += f':type="{group}" '
        m_query += f':sid="legacy:585956" ' if not html else f':sid="confluence:45734834" '
        m_query += f':content="{group} content" ' if not html else f':content="<h1><span>Summary</span></h1><p>Active since" '
        m_query += f':published=2019-08-08T23:15:13]'
        resp = await read_async(logging.getLogger(__name__), cortex_db.conn(), m_query)
        m_id = extract_id(resp)
        return m_id

    async def create_file(num, cortex_db):
        f_query = '[file:bytes="*" '
        f_query += f':mime=x-ibm/report-{group} :name={group}{num}.md '
        f_query += ':size=7890 .seen=2019-08-08T23:15:13]'
        resp = await read_async(logging.getLogger(__name__), cortex_db.conn(), f_query)
        f_id = extract_id(resp)
        return f_id

    async def create_source(num, cortex_db):
        s_query = '[file:bytes="*" '
        s_query += f':mime=x-ibm/report-{group} :name={group}{num}source.md '
        s_query += ':size=7890 .seen=2019-08-08T23:15:13]'
        resp = await read_async(logging.getLogger(__name__), cortex_db.conn(), s_query)
        s_id = extract_id(resp)
        return s_id

    async with cortex_db:
        for num in range(0, max_num):
            f_id = await create_file(num, cortex_db)
            s_id = await create_source(num, cortex_db)
            m_id = await create_news(f_id, s_id, num, cortex_db, html)
            r_list.extend((m_id, f_id))
    return r_list


async def add_domain_nodes(cortex_db, max_num, f_guid):
    d_list = []
    domain = 'domain.com'
    async with cortex_db:
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
        for num in range(1, max_num + 1):
            d_insrt = str(num) + domain
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                        (('inet:fqdn', d_insrt),))
            await add_edge_refs(cortex_db, 'inet:fqdn', d_insrt, f_guid)
            d_list.append(d_insrt)
    return d_list


async def add_ip_nodes(cortex_db, max_num, f_guid):
    i_list = []
    async with cortex_db:
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
        for num in range(1, max_num + 1):
            i_insrt = '{0}.{0}.{0}.{0}'.format(str(num))
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                         (('inet:ipv4', i_insrt),))
            await add_edge_refs(cortex_db, 'inet:ipv4', i_insrt, f_guid)
            i_list.append(i_insrt)
    return i_list


async def add_hash_nodes(cortex_db, max_num, f_guid):
    h_list = []
    hashs = '06be00b6796ea13a38950d3da1b5dee'
    async with cortex_db:
        syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
        for num in range(1, max_num + 1):
            h_insrt = str(num) + hashs
            await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                         (('hash:md5', h_insrt),))
            await add_edge_refs(cortex_db, 'hash:md5', h_insrt, f_guid)
            h_list.append(h_insrt)
    return h_list

async def add_edge_refs(cortex_db, form, prop, f_guid):
    async with cortex_db:
        query = f'[edge:refs=((media:news, {f_guid}), ({form}, {prop}))]'
        result = await read_async(logging.getLogger(__name__), cortex_db.conn(), query)
    return result


async def modify_tags(cortex_db, forms, tags, op):
    new_string = ''
    async with cortex_db:
        for tag in tags:
            await read_async(None, cortex_db.conn(), f'[syn:tag={tag}]')
            new_string += '+#%s ' % tag if op == 'add' else '-#%s ' % tag
            result = await read_async(None, cortex_db.conn(), f'{forms} [{new_string}]')
    return result

def return_userctx():
    uctx = UserContext(1000, 'george@ibm.com', '111111111', OperationSource.simple)
    return uctx


@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestReportFeed:
    # Testing Client fetch
    async def test_industry_feed(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            tags = ['int.entitle.free']
            await add_report(cortex_db, 'industry', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('industry', None)
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-industry'
        assert 'id' in result['data'][0]
        assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
        assert result['data'][0]['entitlement'] == 'free'
        assert result['data'][0]['title'] == 'industry title 0'

    # Testing Developer fetch
    async def test_industry_feed_dev(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            tags = ['int.entitle.free']
            await add_report(cortex_db, 'industry', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('industry', 'dev')
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-industry'
        assert 'id' in result['data'][0]
        assert result['data'][0]['fileName'] == 'industry0.md'
        assert result['data'][0]['size'] == 7890
        assert result['data'][0]['title'] == 'industry title 0'

    # Testing Client fetch
    async def test_threatgroup_feed(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            tags = ['int.entitle.free']
            await add_report(cortex_db, 'threatgroup', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('threatgroup', None)
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-threatgroup'
        assert 'id' in result['data'][0]
        assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
        assert result['data'][0]['entitlement'] == 'free'
        assert result['data'][0]['title'] == 'threatgroup title 0'

    # Testing Developer fetch
    async def test_threatgroup_feed_dev(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            tags = ['int.entitle.free']
            await add_report(cortex_db, 'threatgroup', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('threatgroup', 'dev')
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-threatgroup'
        assert 'id' in result['data'][0]
        assert result['data'][0]['title'] == 'threatgroup title 0'
        assert result['data'][0]['size'] == 7890

    # Testing Client fetch
    async def test_malware_feed(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            await add_report(cortex_db, 'malware', 1)
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('malware', None)
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-malware'
        assert 'id' in result['data'][0]
        assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
        assert result['data'][0]['entitlement'] == 'premium'
        assert result['data'][0]['title'] == 'malware title 0'

    # Testing Developer fetch
    async def test_malware_feed_dev(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            await add_report(cortex_db, 'malware', 1)
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('malware', 'dev')
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-malware'
        assert 'id' in result['data'][0]
        assert result['data'][0]['title'] == 'malware title 0'
        assert result['data'][0]['size'] == 7890

    # Testing Client fetch
    async def test_threatactivity_feed(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            tags = ['int.entitle.premium']
            await add_report(cortex_db, 'threat-activity', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('threatactivity', None)
        assert len(result['data']) == 1
        assert result['data'][0]['content-type'] == 'x-ibm/report-threatactivity'
        assert 'id' in result['data'][0]
        assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
        assert result['data'][0]['entitlement'] == 'premium'
        assert result['data'][0]['title'] == 'threat-activity title 0'

    # Testing Developer fetch
    async def test_threatactivity_feed_dev(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            tags = ['int.entitle.premium']
            await add_report(cortex_db, 'threat-activity', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch('threatactivity','dev')
        assert len(result['data']) == 1

    # Testing Client fetch
    async def test_all_feed(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 3 reports
            await add_report(cortex_db, 'malware', 1)
            await add_report(cortex_db, 'industry', 1)
            await add_report(cortex_db, 'threatgroup', 1)
            await add_report(cortex_db, 'threat-activity', 1)
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(None, None)
        assert len(result['data']) == 4
        for data in result['data']:
            if data['content-type'] in ['x-ibm/report-malware', 'x-ibm/report-threatgroup', 'x-ibm/report-industry', 'x-ibm/report-threatactivity']:
                assert data['modified'] == '2019-08-08T23:15:13Z'
                assert data['entitlement'] == 'premium'
                assert 'title 0' in data['title']

    # Testing Developer fetch
    async def test_all_feed_dev(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 3 reports
            await add_report(cortex_db, 'malware', 1)
            await add_report(cortex_db, 'industry', 1)
            await add_report(cortex_db, 'threatgroup', 1)
            await add_report(cortex_db, 'threat-activity', 1)
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(None, 'dev')
        assert len(result['data']) == 4
        for data in result['data']:
            if data['content-type'] in ['x-ibm/report-malware', 'x-ibm/report-threatgroup', 'x-ibm/report-industry']:
                assert 'title 0' in data['title']
                assert result['data'][0]['size'] == 7890

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestReportFetch:
    async def test_fetch_industry_report(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 industry report
            tags = ['int.entitle.free']
            guid_list = await add_report(cortex_db, 'industry', 1)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == 'industry content'
        assert result['data']['content-type'] == 'x-ibm/report-industry'
        assert 'created' in result['data']
        assert 'source_pdf' in result['data']
        assert result['data']['entitlement'] == 'free'
        assert result['data']['indicators'] == []
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == 'industry summary'
        assert result['data']['tags'].sort() == ['int.entitle.free'].sort()
        assert result['data']['title'] == 'industry title 0'
        assert result['data']['source'] == 'legacy'

    async def test_fetch_industry_report_html(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 industry report
            tags = ['int.entitle.free']
            guid_list = await add_report(cortex_db, 'industry', 1, html=True)
            await modify_tags(cortex_db, 'media:news', tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == '# Summary\n\nActive since\n'
        assert result['data']['content-type'] == 'x-ibm/report-industry'
        assert 'created' in result['data']
        assert 'source_pdf' in result['data']
        assert result['data']['entitlement'] == 'free'
        assert result['data']['indicators'] == []
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == ''
        assert result['data']['tags'].sort() == ['int.entitle.free'].sort()
        assert result['data']['title'] == 'industry title 0'
        assert result['data']['source'] == 'confluence'

    async def test_fetch_malware_report(self):
        m_forms = 'media:news'
        m_tags = ['mal.fallchill', 'bhv.test']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['mal.gen', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 malware report
            guid_list = await add_report(cortex_db, 'malware', 1)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, m_forms, m_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == 'malware content'
        assert result['data']['content-type'] == 'x-ibm/report-malware'
        assert 'created' in result['data']
        assert result['data']['entitlement'] == 'premium'
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == 'malware summary'
        assert result['data']['tags'].sort() == ['mal.fallchill', 'bhv.test'].sort()
        assert result['data']['title'] == 'malware title 0'
        for ioc in result['data']['indicators']:
            assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
            assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
            assert 'seen' in ioc
            assert ioc['tags'].sort() == ['mal.gen', 'trend.test'].sort()

    async def test_fetch_malware_report_html(self):
        m_forms = 'media:news'
        m_tags = ['mal.fallchill', 'bhv.test']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['mal.gen', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 malware report
            guid_list = await add_report(cortex_db, 'malware', 1, html=True)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, m_forms, m_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == '# Summary\n\nActive since\n'
        assert result['data']['content-type'] == 'x-ibm/report-malware'
        assert 'created' in result['data']
        assert result['data']['entitlement'] == 'premium'
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == ''
        assert result['data']['tags'].sort() == ['mal.fallchill', 'bhv.test'].sort()
        assert result['data']['title'] == 'malware title 0'
        for ioc in result['data']['indicators']:
            assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
            assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
            assert 'seen' in ioc
            assert ioc['tags'].sort() == ['mal.gen', 'trend.test'].sort()

    async def test_fetch_threatgroup_report(self):
        m_forms = 'media:news'
        m_tags = ['thr.itgtest0']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['tgt.test', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 threatgroup report
            guid_list = await add_report(cortex_db, 'threatgroup', 1)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, m_forms, m_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == 'threatgroup content'
        assert result['data']['content-type'] == 'x-ibm/report-threatgroup'
        assert 'created' in result['data']
        assert result['data']['entitlement'] == 'premium'
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == 'threatgroup summary'
        assert result['data']['tags'].sort() == ['tgt.test', 'thr.itgtest0', 'trend.test'].sort() #should include intsum
        assert result['data']['title'] == 'threatgroup title 0'
        for ioc in result['data']['indicators']:
            assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
            assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
            assert 'seen' in ioc
            assert ioc['tags'].sort() == ['tgt.test', 'trend.test'].sort()

    async def test_fetch_threatgroup_report_html(self):
        m_forms = 'media:news'
        m_tags = ['thr.itgtest0']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['tgt.test', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 threatgroup report
            guid_list = await add_report(cortex_db, 'threatgroup', 1, html=True)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, m_forms, m_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == '# Summary\n\nActive since\n'
        assert result['data']['content-type'] == 'x-ibm/report-threatgroup'
        assert 'created' in result['data']
        assert result['data']['entitlement'] == 'premium'
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == ''
        assert result['data']['tags'].sort() == ['tgt.test', 'thr.itgtest0', 'trend.test'].sort() #should include intsum
        assert result['data']['title'] == 'threatgroup title 0'
        for ioc in result['data']['indicators']:
            assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
            assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
            assert 'seen' in ioc
            assert ioc['tags'].sort() == ['tgt.test', 'trend.test'].sort()

    async def test_fetch_threatactivity_report(self):
        m_forms = 'media:news'
        m_tags = ['int.jira.iris.7451']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['mal.gen', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 threatactivity report
            guid_list = await add_report(cortex_db, 'threat-activity', 1)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, m_forms, m_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0])
        assert result['data']['content'] == 'threat-activity content'
        assert result['data']['content-type'] == 'x-ibm/report-threatactivity'
        assert 'created' in result['data']
        assert result['data']['entitlement'] == 'premium'
        assert result['data']['published'] == '2019-08-08T23:15:13Z'
        assert result['data']['summary'] == 'threat-activity summary'
        assert result['data']['tags'].sort() == ['int.jira.iris.7451'].sort()
        assert result['data']['title'] == 'threat-activity title 0'
        for ioc in result['data']['indicators']:
            assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
            assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
            assert 'seen' in ioc
            assert ioc['tags'].sort() == ['mal.gen', 'trend.test'].sort()

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestReportFetchSTIX:
    async def test_fetch_industry_report_stix(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 industry report
            guid_list = await add_report(cortex_db, 'industry', 1)
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0], fmt_type='stix')
        current_time = time.strftime('%m-%d-%YZ', time.gmtime())
        assert len(result['data']) == 4
        assert len(result['data']['objects']) == 2

    async def test_fetch_malware_report_stix(self):
        f_forms = 'media:news'
        f_tags = ['mal.fallchill']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['mal.gen', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 malware report
            guid_list = await add_report(cortex_db, 'malware', 1)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, f_forms, f_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0], fmt_type='stix')
        current_time = time.strftime('%m-%d-%YZ', time.gmtime())
        assert len(result['data']) == 4
        assert len(result['data']['objects']) == 5

    async def test_fetch_threatgroup_report_stix(self):
        f_forms = 'media:news'
        f_tags = ['thr.itgtest0']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['tgt.test', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 threatgroup report
            guid_list = await add_report(cortex_db, 'threatgroup', 1)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, f_forms, f_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0], fmt_type='stix')
        current_time = time.strftime('%m-%d-%YZ', time.gmtime())
        assert len(result['data']) == 4
        assert len(result['data']['objects']) == 5

    async def test_fetch_threatactivity_report_stix(self):
        f_forms = 'media:news'
        f_tags = ['int.jira.iris']
        i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
        i_tags = ['mal.gen', 'trend.test']
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        async with cortex_db:
            # add 1 threat-activity report
            guid_list = await add_report(cortex_db, 'threatactivity', 1)
            await add_nodes(cortex_db, 'domain', 1, guid_list[0])
            await add_nodes(cortex_db, 'ip', 1, guid_list[0])
            await add_nodes(cortex_db, 'hash', 1, guid_list[0])
            await modify_tags(cortex_db, f_forms, f_tags, 'add')
            await modify_tags(cortex_db, i_forms, i_tags, 'add')
            rf_op = ReportFactory(logging.getLogger(
                __name__), cortex_db=cortex_db)
            result = await rf_op.fetch(guid_list[0], fmt_type='stix')
        current_time = time.strftime('%m-%d-%YZ', time.gmtime())
        assert len(result['data']) == 4
        assert len(result['data']['objects']) == 5


    async def test_create_stix_report_error(self):
        logger = logging.getLogger(__name__)
        mock = MalwareReports.malware_bad_properties()
        stix_cls = StixBundle(mock, logger)
        with pytest.raises(StixTranslationError):
            stix_cls.create()

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestReportIngest:
    def ret_mock(self):
        mock = {}
        mock['tufos'] = []
        mock['tufos'].append({
            'type': 'inet:fqdn',
            'property': 'google.com'
        })
        mock['tufos'].append({
            'type': 'inet:fqdn',
            'property': 'expel.io'
        })
        mock['tufos'].append({
            'type': 'inet:ipv4',
            'property': '8.8.8.8'
        })
        mock['fileName'] = 'test.md'
        mock['size'] = 7890
        mock['content'] = {'author': 'Test',
                           'org': 'IBM',
                           'title': 'Testing Title',
                           'summary': 'Testing Summary'
                           }
        mock['file'] = 'Testing content'
        return mock

    async def create_file(self, num, c_type, cortex_db):
        f_query = '[file:bytes="*" '
        f_query += f':mime={c_type} :name=test{num}.md '
        f_query += ':size=7890 .seen=2019-08-08T23:15:13]'
        resp = await read_async(logging.getLogger(__name__), cortex_db.conn(), f_query)
        n_property = ''
        for node in resp:
            if node[0] == 'node':
                n_property = node[1][0][1]
        return n_property

    async def test_ingest_report_malware(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-malware'
        mock['tags'] = ['mal.wannacry', 'bhv.test']
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            f_id = await self.create_file(1, 'malware', cortex_db)
            mock['id'] = f_id
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            i_result = await rf_op.ingest(mock)
        assert i_result['data']['content'] == 'Testing content'
        assert i_result['data']['content-type'] == 'x-ibm/report-malware'
        assert i_result['data']['entitlement'] == 'premium'
        assert i_result['data']['summary'] == 'Testing Summary'
        assert i_result['data']['tags'].sort() == ['mal.wannacry', 'bhv.test'].sort()
        assert i_result['data']['title'] == 'Testing Title'
        for ioc in i_result['data']['indicators']:
            assert ioc['indicator'] in ['google.com', 'expel.io', '8.8.8.8']
            assert ioc['type'] in ['inet:fqdn', 'inet:ipv4']
            assert 'seen' in ioc
            assert ioc['tags'] == []

    async def test_ingest_report_threatgroup(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-threatgroup'
        mock['tags'] = ['thr.itg01', 'bhv.test']
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            f_id = await self.create_file(1, 'threatgroup', cortex_db)
            mock['id'] = f_id
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            i_result = await rf_op.ingest(mock)
        assert i_result['data']['content'] == 'Testing content'
        assert i_result['data']['content-type'] == 'x-ibm/report-threatgroup'
        assert i_result['data']['entitlement'] == 'premium'
        assert i_result['data']['summary'] == 'Testing Summary'
        assert i_result['data']['tags'].sort() == ['thr.itg01', 'bhv.test'].sort()
        assert i_result['data']['title'] == 'Testing Title'
        for ioc in i_result['data']['indicators']:
            assert ioc['indicator'] in ['google.com', 'expel.io', '8.8.8.8']
            assert ioc['type'] in ['inet:fqdn', 'inet:ipv4']
            assert 'seen' in ioc
            assert ioc['tags'] == []

    async def test_ingest_report_industry(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-industry'
        mock['tags'] = ['trend.ind.finance', 'bhv.test']
        mock['tufos'] = []
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            f_id = await self.create_file(1, 'industry', cortex_db)
            mock['id'] = f_id
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            i_result = await rf_op.ingest(mock)
        assert i_result['data']['content'] == 'Testing content'
        assert i_result['data']['content-type'] == 'x-ibm/report-industry'
        assert i_result['data']['entitlement'] == 'premium'
        assert i_result['data']['summary'] == 'Testing Summary'
        assert i_result['data']['tags'].sort() == ['trend.ind.finance', 'bhv.test'].sort()
        assert i_result['data']['title'] == 'Testing Title'
        assert i_result['data']['indicators'] == []

    async def test_ingest_report_threatactivity(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-threatactivity'
        mock['tags'] = ['int.entitle.premium', 'bhv.test']
        mock['tufos'] = []
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            f_id = await self.create_file(1, 'threat-activity', cortex_db)
            mock['id'] = f_id
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            with pytest.raises(Exception):
                await rf_op.ingest(mock)

    async def test_ingest_report_industry_no_tags(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-industry'
        mock['tags'] = []
        mock['tufos'] = []
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            f_id = await self.create_file(1, 'industry', cortex_db)
            mock['id'] = f_id
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            i_result = await rf_op.ingest(mock)
        assert i_result['data']['content'] == 'Testing content'
        assert i_result['data']['content-type'] == 'x-ibm/report-industry'
        assert i_result['data']['entitlement'] == 'premium'
        assert i_result['data']['summary'] == 'Testing Summary'
        assert i_result['data']['tags'] == []
        assert i_result['data']['title'] == 'Testing Title'
        assert i_result['data']['indicators'] == []

    async def test_ingest_report_media_news_existing(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-malware'
        mock['tags'] = ['mal.wannacry', 'bhv.test']
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            guid_list = await add_report(cortex_db, 'malware', 1)
            mock['id'] = guid_list[1]
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            i_result = await rf_op.ingest(mock)
        assert i_result['data']['content'] == 'Testing content'
        assert i_result['data']['content-type'] == 'x-ibm/report-malware'
        assert i_result['data']['entitlement'] == 'premium'
        assert i_result['data']['summary'] == 'Testing Summary'
        assert i_result['data']['tags'].sort() == ['mal.wannacry', 'bhv.test'].sort()
        assert i_result['data']['title'] == 'Testing Title'
        for ioc in i_result['data']['indicators']:
            assert ioc['indicator'] in ['google.com', 'expel.io', '8.8.8.8']
            assert ioc['type'] in ['inet:fqdn', 'inet:ipv4']
            assert 'seen' in ioc
            assert ioc['tags'] == []

    async def test_ingest_report_no_file_bytes(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        mock = self.ret_mock()
        mock['content-type'] = 'x-ibm/report-malware'
        mock['tags'] = ['int.entitle.premium', 'bhv.test']
        mock['tufos'] = []
        async with cortex_db:
            # Creating file:bytes <- pre-req to reports existing
            mock['id'] = 'sha256:9e425471a5bc3ea77479c603c9c23ae9c0b820d0a0af9f081db3b4b636131de2'
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            with pytest.raises(Exception):
                await rf_op.ingest(mock)

    async def test_update_published(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=syn_mods)
        db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
        uctx = return_userctx()
        async with cortex_db:
            guid_list = await add_report(cortex_db, 'malware', 1)
            rf_op = ReportFactory(logging.getLogger(__name__),
                                  userctx=uctx,
                                  db_node_history=db_node_history,
                                  cortex_db=cortex_db)
            p_result = await rf_op.set_published(guid_list[0])
        assert 'id' in p_result['data']
        assert 'published' in p_result['data']