# import pytest
# import logging
# import time
# from libs.config import set_root_dir, set_profile, find_config_dir
# from libs.cortex_db import CortexDb, read_async
# from libs.reports.transforms import ReportFactory
# from libs.db_node_history import DbNodeHistory, ArangoConfig
# from libs.userctx import OperationSource, UserContext
# from libs.synapse_nodes import Tufo
# from test.unit.report_mocks.malware_mock import MalwareReports
# from libs.reports.stix.create_stix_report import StixBundle
# from helpers.http_errors import StixTranslationError
#
# media_mod = 'config.models.media.MediaModule'
#
# @pytest.fixture(scope='session')
# def setup_config():
#     set_root_dir(find_config_dir())
#     set_profile('test')
#     return True
#
#
# async def add_nodes(cortex_db, ioc_type, max_num, f_guid):
#     n_list = []
#     current_time = time.strftime('%Y-%m-%dZ', time.gmtime())
#     d_tags = ['mal.wannacry', 'pwn.test',
#               'code.test', 'tgt.test',
#               'bookmark.test', 'review.test',
#               'int.test', 'thr.test',
#               'bhv.test', 'trend.test']
#     op_type = {
#         'domain': add_domain_nodes,
#         'hash': add_hash_nodes,
#         'ip': add_ip_nodes,
#     }
#     n_list = await op_type[ioc_type](cortex_db, max_num, f_guid)
#     return (n_list, current_time)
#
#
# async def add_report(cortex_db, group, max_num, r_type="test", content="test"):
#     r_list = []
#     name = 'test'
#     # current_time = time.strftime('%Y-%m-%d', time.gmtime())
#     async with cortex_db:
#         for num in range(0, max_num):
#             f_insrt = name + str(num)
#             f_query = f'[file:bytes="*" :mime=x-ibm/report-{group} :name={f_insrt}.md :size=7890 .seen=2019-08-08T23:15:13]'
#             f_result = await read_async(logging.getLogger(__name__), cortex_db.conn(), f_query)
#             for node in f_result:
#                 if node[0] == 'node':
#                     f_property = node[1][0][1]
#                     m_query = f'[media:news="*" :title={f_insrt} :summary="{f_insrt} summary" :file={f_property} :org=IBM :author=test :type="{r_type}" :content="{content}"]'
#                     m_result = await read_async(logging.getLogger(__name__), cortex_db.conn(), m_query)
#             r_list.append(f_property)
#         if group == 'threatactivity':
#             await modify_tags(cortex_db, 'file:bytes', ['int.jira.iris'], 'add')
#     return r_list
#
#
# async def add_domain_nodes(cortex_db, max_num, f_guid):
#     d_list = []
#     domain = 'domain.com'
#     async with cortex_db:
#         syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
#         for num in range(1, max_num + 1):
#             d_insrt = str(num) + domain
#             await syn_tufo.add_test_nodes(None, cortex_db.conn(),
#                                         (('inet:fqdn', d_insrt),))
#             await add_edge_refs(cortex_db, 'inet:fqdn', d_insrt, f_guid)
#             d_list.append(d_insrt)
#     return d_list
#
#
# async def add_ip_nodes(cortex_db, max_num, f_guid):
#     i_list = []
#     async with cortex_db:
#         syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
#         for num in range(1, max_num + 1):
#             i_insrt = '{0}.{0}.{0}.{0}'.format(str(num))
#             await syn_tufo.add_test_nodes(None, cortex_db.conn(),
#                                          (('inet:ipv4', i_insrt),))
#             await add_edge_refs(cortex_db, 'inet:ipv4', i_insrt, f_guid)
#             i_list.append(i_insrt)
#     return i_list
#
#
# async def add_hash_nodes(cortex_db, max_num, f_guid):
#     h_list = []
#     hashs = '06be00b6796ea13a38950d3da1b5dee'
#     async with cortex_db:
#         syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
#         for num in range(1, max_num + 1):
#             h_insrt = str(num) + hashs
#             await syn_tufo.add_test_nodes(None, cortex_db.conn(),
#                                          (('hash:md5', h_insrt),))
#             await add_edge_refs(cortex_db, 'hash:md5', h_insrt, f_guid)
#             h_list.append(h_insrt)
#     return h_list
#
# async def add_edge_refs(cortex_db, form, prop, f_guid):
#     async with cortex_db:
#         query = f'[edge:refs=((file:bytes, {f_guid}), ({form}, {prop}))]'
#         result = await read_async(logging.getLogger(__name__), cortex_db.conn(), query)
#     return result
#
#
# async def modify_tags(cortex_db, forms, tags, op):
#     new_string = ''
#     async with cortex_db:
#         for tag in tags:
#             await read_async(None, cortex_db.conn(), f'[syn:tag={tag}]')
#             new_string += '+#%s ' % tag if op == 'add' else '-#%s ' % tag
#             result = await read_async(None, cortex_db.conn(), f'{forms} [{new_string}]')
#     return result
#
# def return_userctx():
#     uctx = UserContext(1000, 'george@ibm.com', '111111111', OperationSource.simple)
#     return uctx
#
#
# def r_mock():
#     return {
#         'msg': 'success',
#         'status': 0,
#         'data': {
#             'report': 'test report content',
#             'title': 'test0',
#             'summary': 'test0 summary'
#         }
#     }
#
# def i_mock():
#     return {
#             "fileName": "test0.md",
#             "size": 7890,
#             "content-type": "",
#             "tufos": [],
#             "tags": [],
#             "content": {
#                 "author": "IBM",
#                 "org": "IBM",
#                 "title": "test0",
#                 "summary": "test0 summary"
#             }
#         }
#
#
# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestReportFeed:
#     async def test_industry_feed(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 industry report
#             await add_report(cortex_db, 'industry', 1)
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch('industry', None)
#         assert len(result['data']) == 1
#         assert result['data'][0]['content-type'] == 'x-ibm/report-industry'
#         assert result['data'][0]['fileName'] == 'test0.md'
#         assert 'guid' in result['data'][0]['id']
#         assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
#         assert result['data'][0]['published'] == ''
#         assert result['data'][0]['size'] == 7890
#         assert result['data'][0]['title'] == 'test0'
#
#     async def test_threatgroup_feed(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 threatgroup report
#             await add_report(cortex_db, 'threatgroup', 1)
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch('threatgroup', None)
#         assert len(result['data']) == 1
#         assert result['data'][0]['content-type'] == 'x-ibm/report-threatgroup'
#         assert result['data'][0]['fileName'] == 'test0.md'
#         assert 'guid' in result['data'][0]['id']
#         assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
#         assert result['data'][0]['published'] == ''
#         assert result['data'][0]['size'] == 7890
#         assert result['data'][0]['title'] == 'test0'
#
#     async def test_malware_feed(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 malware report
#             await add_report(cortex_db, 'malware', 1)
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch('malware', None)
#         assert len(result['data']) == 1
#         assert result['data'][0]['content-type'] == 'x-ibm/report-malware'
#         assert result['data'][0]['fileName'] == 'test0.md'
#         assert 'guid' in result['data'][0]['id']
#         assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
#         assert result['data'][0]['published'] == ''
#         assert result['data'][0]['size'] == 7890
#         assert result['data'][0]['title'] == 'test0'
#
#     async def test_threatactivity_feed(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 threatactivity report
#             await add_report(cortex_db, 'threatactivity', 1, r_type="threat-activity", content="This is a threat report")
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch('threatactivity', None)
#         assert len(result['data']) == 1
#         assert result['data'][0]['content-type'] == 'x-ibm/report-threatactivity'
#         assert result['data'][0]['fileName'] == 'test0.md'
#         assert 'guid' in result['data'][0]['id']
#         assert result['data'][0]['modified'] == '2019-08-08T23:15:13Z'
#         assert result['data'][0]['published'] == ''
#         assert result['data'][0]['size'] == 7890
#         assert result['data'][0]['title'] == 'test0'
#
#     async def test_all_feed(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 3 reports
#             await add_report(cortex_db, 'malware', 1, r_type="malware", content="This is a threat report")
#             await add_report(cortex_db, 'industry', 1, r_type="industry", content="This is a threat report")
#             await add_report(cortex_db, 'threatgroup', 1, r_type="threat-group", content="This is a threat report")
#             await add_report(cortex_db, 'threatactivity', 1, r_type="threat-activity", content="This is a threat report")
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(None, None)
#         assert len(result['data']) == 4
#         for data in result['data']:
#             if data['content-type'] in ['x-ibm/report-malware', 'x-ibm/report-threatgroup', 'x-ibm/report-industry', 'x-ibm/report-threatactivity']:
#                 assert data['fileName'] == 'test0.md'
#                 assert 'guid' in data['id']
#                 assert data['modified'] == '2019-08-08T23:15:13Z'
#                 assert data['published'] == ''
#                 assert data['size'] == 7890
#                 assert data['title'] == 'test0'
#
# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestReportFetch:
#     async def test_fetch_industry_report(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 industry report
#             guid_list = await add_report(cortex_db, 'industry', 1)
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], None, mock=r_mock())
#         assert result['data']['content'] == 'test report content'
#         assert result['data']['content-type'] == 'x-ibm/report-industry'
#         assert 'created' in result['data']
#         assert result['data']['entitlement'] == 'premium'
#         assert result['data']['fileName'] == 'test0.md'
#         assert result['data']['indicators'] == []
#         assert result['data']['primary_tag'] == ''
#         assert result['data']['published'] == ''
#         assert result['data']['summary'] == 'test0 summary'
#         assert result['data']['tags'] == []
#         assert result['data']['title'] == 'test0'
#
#     async def test_fetch_malware_report(self):
#         f_forms = 'file:bytes'
#         f_tags = ['mal.fallchill']
#         t_forms = 'syn:tag'
#         t_tags = ['bhv.test']
#         i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
#         i_tags = ['mal.gen', 'trend.test']
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 malware report
#             guid_list = await add_report(cortex_db, 'malware', 1)
#             await add_nodes(cortex_db, 'domain', 1, guid_list[0])
#             await add_nodes(cortex_db, 'ip', 1, guid_list[0])
#             await add_nodes(cortex_db, 'hash', 1, guid_list[0])
#             await modify_tags(cortex_db, f_forms, f_tags, 'add')
#             await modify_tags(cortex_db, t_forms, t_tags, 'add')
#             await modify_tags(cortex_db, i_forms, i_tags, 'add')
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], None, mock=r_mock())
#         assert result['data']['content'] == 'test report content'
#         assert result['data']['content-type'] == 'x-ibm/report-malware'
#         assert 'created' in result['data']
#         assert result['data']['entitlement'] == 'premium'
#         assert result['data']['fileName'] == 'test0.md'
#         assert result['data']['primary_tag'] == 'mal.fallchill'
#         assert result['data']['published'] == ''
#         assert result['data']['summary'] == 'test0 summary'
#         assert result['data']['tags'].sort() == ['mal.fallchill', 'bhv.test'].sort() #should include malware family tags
#         assert result['data']['title'] == 'test0'
#         for ioc in result['data']['indicators']:
#             assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
#             assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
#             assert 'seen' in ioc
#             assert ioc['tags'].sort() == ['mal.gen', 'trend.test'].sort()
#
#     async def test_fetch_threatgroup_report(self):
#         f_forms = 'file:bytes'
#         f_tags = ['thr.itgtest0']
#         i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
#         i_tags = ['tgt.test', 'trend.test']
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 threatgroup report
#             guid_list = await add_report(cortex_db, 'threatgroup', 1)
#             await add_nodes(cortex_db, 'domain', 1, guid_list[0])
#             await add_nodes(cortex_db, 'ip', 1, guid_list[0])
#             await add_nodes(cortex_db, 'hash', 1, guid_list[0])
#             await modify_tags(cortex_db, f_forms, f_tags, 'add')
#             await modify_tags(cortex_db, i_forms, i_tags, 'add')
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], None, mock=r_mock())
#         assert result['data']['content'] == 'test report content'
#         assert result['data']['content-type'] == 'x-ibm/report-threatgroup'
#         assert 'created' in result['data']
#         assert result['data']['entitlement'] == 'premium'
#         assert result['data']['fileName'] == 'test0.md'
#         assert result['data']['primary_tag'] == 'thr.itgtest0'
#         assert result['data']['published'] == ''
#         assert result['data']['summary'] == 'test0 summary'
#         assert result['data']['tags'].sort() == ['tgt.test', 'thr.itgtest0', 'trend.test'].sort() #should include intsum
#         assert result['data']['title'] == 'test0'
#         for ioc in result['data']['indicators']:
#             assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
#             assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
#             assert 'seen' in ioc
#             assert ioc['tags'].sort() == ['tgt.test', 'trend.test'].sort()
#
#     async def test_fetch_threatactivity_report(self):
#         f_forms = 'file:bytes'
#         f_tags = ['int.jira.iris.7451']
#         t_forms = 'syn:tag'
#         t_tags = ['bhv.test']
#         i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
#         i_tags = ['mal.gen', 'trend.test']
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 threatactivity report
#             guid_list = await add_report(cortex_db, 'threatactivity', 1, r_type="threat-activity", content="This is a threat report")
#             await add_nodes(cortex_db, 'domain', 1, guid_list[0])
#             await add_nodes(cortex_db, 'ip', 1, guid_list[0])
#             await add_nodes(cortex_db, 'hash', 1, guid_list[0])
#             await modify_tags(cortex_db, f_forms, f_tags, 'add')
#             await modify_tags(cortex_db, t_forms, t_tags, 'add')
#             await modify_tags(cortex_db, i_forms, i_tags, 'add')
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], None)
#         assert result['data']['content'] == 'This is a threat report\n\n'
#         assert result['data']['content-type'] == 'x-ibm/report-threatactivity'
#         assert 'created' in result['data']
#         assert result['data']['entitlement'] == 'premium'
#         assert result['data']['fileName'] == 'N/A'
#         assert result['data']['published'] == ''
#         assert result['data']['summary'] == 'N/A'
#         assert result['data']['tags'].sort() == ['int.jira.iris.7451'].sort()
#         assert result['data']['title'] == 'test0'
#         for ioc in result['data']['indicators']:
#             assert ioc['indicator'] in ['1.1.1.1', '106be00b6796ea13a38950d3da1b5dee', '1domain.com']
#             assert ioc['type'] in ['inet:ipv4', 'inet:fqdn', 'hash:md5']
#             assert 'seen' in ioc
#             assert ioc['tags'].sort() == ['mal.gen', 'trend.test'].sort()
#
# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestReportFetchSTIX:
#     async def test_fetch_industry_report(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 industry report
#             guid_list = await add_report(cortex_db, 'industry', 1,  r_type="industry", content="This is a threat report")
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], fmt_type='stix', mock=r_mock())
#         current_time = time.strftime('%m-%d-%YZ', time.gmtime())
#         assert len(result['data']) == 4
#         assert len(result['data']['objects']) == 2
#
#     async def test_fetch_malware_report(self):
#         f_forms = 'file:bytes'
#         f_tags = ['mal.fallchill']
#         t_forms = 'syn:tag'
#         t_tags = ['bhv.test']
#         i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
#         i_tags = ['mal.gen', 'trend.test']
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 malware report
#             guid_list = await add_report(cortex_db, 'malware', 1,  r_type="malware", content="This is a threat report")
#             await add_nodes(cortex_db, 'domain', 1, guid_list[0])
#             await add_nodes(cortex_db, 'ip', 1, guid_list[0])
#             await add_nodes(cortex_db, 'hash', 1, guid_list[0])
#             await modify_tags(cortex_db, f_forms, f_tags, 'add')
#             await modify_tags(cortex_db, t_forms, t_tags, 'add')
#             await modify_tags(cortex_db, i_forms, i_tags, 'add')
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], fmt_type='stix', mock=r_mock())
#         current_time = time.strftime('%m-%d-%YZ', time.gmtime())
#         assert len(result['data']) == 4
#         assert len(result['data']['objects']) == 5
#
#     async def test_fetch_threatgroup_report(self):
#         f_forms = 'file:bytes'
#         f_tags = ['thr.itgtest0']
#         i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
#         i_tags = ['tgt.test', 'trend.test']
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 threatgroup report
#             guid_list = await add_report(cortex_db, 'threatgroup', 1,  r_type="threat-group", content="This is a threat report")
#             await add_nodes(cortex_db, 'domain', 1, guid_list[0])
#             await add_nodes(cortex_db, 'ip', 1, guid_list[0])
#             await add_nodes(cortex_db, 'hash', 1, guid_list[0])
#             await modify_tags(cortex_db, f_forms, f_tags, 'add')
#             await modify_tags(cortex_db, i_forms, i_tags, 'add')
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], fmt_type='stix', mock=r_mock())
#         current_time = time.strftime('%m-%d-%YZ', time.gmtime())
#         assert len(result['data']) == 4
#         assert len(result['data']['objects']) == 5
#
#     async def test_fetch_threatactivity_report(self):
#         f_forms = 'file:bytes'
#         f_tags = ['int.jira.iris']
#         t_forms = 'syn:tag'
#         t_tags = ['bhv.test']
#         i_forms = 'hash:md5 inet:ipv4 inet:fqdn'
#         i_tags = ['mal.gen', 'trend.test']
#         cortex_db = CortexDb(logging.getLogger(__name__), True, load_mod=media_mod)
#         async with cortex_db:
#             # add 1 threat-activity report
#             guid_list = await add_report(cortex_db, 'threatactivity', 1, r_type="threat-activity", content="This is a threat report")
#             await add_nodes(cortex_db, 'domain', 1, guid_list[0])
#             await add_nodes(cortex_db, 'ip', 1, guid_list[0])
#             await add_nodes(cortex_db, 'hash', 1, guid_list[0])
#             await modify_tags(cortex_db, f_forms, f_tags, 'add')
#             await modify_tags(cortex_db, t_forms, t_tags, 'add')
#             await modify_tags(cortex_db, i_forms, i_tags, 'add')
#             rf_op = ReportFactory(logging.getLogger(
#                 __name__), cortex_db=cortex_db)
#             result = await rf_op.fetch(guid_list[0], fmt_type='stix')
#         current_time = time.strftime('%m-%d-%YZ', time.gmtime())
#         assert len(result['data']) == 4
#         assert len(result['data']['objects']) == 5
#
#
#     async def test_create_stix_report_error(self):
#         logger = logging.getLogger(__name__)
#         mock = MalwareReports.malware_bad_properties()
#         stix_cls = StixBundle(mock, logger)
#         with pytest.raises(StixTranslationError):
#             stix_cls.create()
#
# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestReportIngest:
#     async def test_ingest_report(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
#         uctx = return_userctx()
#         mock = i_mock()
#         mock['content-type'] = 'X-IBM/Report-malware'
#         mock['tags'] = ['mal.wannacry', 'bhv.test']
#         mock['tufos'] = [{
#                     'type': 'inet:fqdn',
#                     'property': 'google.com'
#                 },
#                 {
#                     'type': 'inet:email',
#                     'property': 'test@ibm.com'
#                 },
#                 {
#                     'type': 'inet:tcp4',
#                     'property': '158.69.199.223:8080'
#                 }]
#         async with cortex_db:
#             rf_op = ReportFactory(logging.getLogger(__name__),
#                                   userctx=uctx,
#                                   db_node_history=db_node_history,
#                                   cortex_db=cortex_db)
#             i_result = await rf_op.ingest(mock)
#             assert(i_result['data']['id'])
#             f_result = await rf_op.fetch(i_result['data']['id'], mock=r_mock())
#         assert i_result['msg'] == 'success'
#         assert i_result['status'] == 0
#         assert 'id' in i_result['data']
#         assert 'published' in i_result['data']
#         assert 'guid' in i_result['data']['id']
#         assert 'created' in f_result['data']
#         assert 'published' in f_result['data']
#         assert f_result['data']['content'] == 'test report content'
#         assert f_result['data']['content-type'] == 'x-ibm/report-malware'
#         assert f_result['data']['entitlement'] == 'premium'
#         assert f_result['data']['fileName'] == 'test0.md'
#         assert f_result['data']['primary_tag'] == 'mal.wannacry'
#         assert f_result['data']['summary'] == 'test0 summary'
#         assert f_result['data']['tags'].sort() == ['mal.wannacry', 'bhv.test'].sort() #should include malware family tags
#         assert f_result['data']['title'] == 'test0'
#         for ioc in f_result['data']['indicators']:
#             assert ioc['indicator'] in ['google.com', 'test@ibm.com']
#             assert ioc['type'] in ['inet:fqdn', 'inet:email']
#             assert 'seen' in ioc
#             assert ioc['tags'] == []
#
#     async def test_remove_report(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
#         uctx = return_userctx()
#         mock = i_mock()
#         mock['content-type'] = 'X-IBM/Report-malware'
#         mock['tags'] = ['mal.wannacry', 'bhv.test']
#         mock['tufos'] = [{
#                     'type': 'inet:fqdn',
#                     'property': 'google.com'
#                 },
#                 {
#                     'type': 'inet:email',
#                     'property': 'test@ibm.com'
#                 }]
#         async with cortex_db:
#             rf_op = ReportFactory(logging.getLogger(__name__),
#                                   userctx=uctx,
#                                   db_node_history=db_node_history,
#                                   cortex_db=cortex_db)
#             i_result = await rf_op.ingest(mock)
#             assert(i_result['data']['id'])
#             f_result = await rf_op.fetch(i_result['data']['id'], mock=r_mock())
#             d_result = await rf_op.remove_report(i_result['data']['id'])
#         assert i_result['msg'] == 'success'
#         assert i_result['status'] == 0
#         assert 'id' in i_result['data']
#         assert 'published' in i_result['data']
#         assert 'guid' in i_result['data']['id']
#         assert 'created' in f_result['data']
#         assert 'published' in f_result['data']
#         assert f_result['data']['content'] == 'test report content'
#         assert f_result['data']['content-type'] == 'x-ibm/report-malware'
#         assert f_result['data']['entitlement'] == 'premium'
#         assert f_result['data']['fileName'] == 'test0.md'
#         assert f_result['data']['primary_tag'] == 'mal.wannacry'
#         assert f_result['data']['summary'] == 'test0 summary'
#         assert f_result['data']['tags'].sort() == ['mal.wannacry', 'bhv.test'].sort() #should include malware family tags
#         assert f_result['data']['title'] == 'test0'
#         for ioc in f_result['data']['indicators']:
#             assert ioc['indicator'] in ['google.com', 'test@ibm.com']
#             assert ioc['type'] in ['inet:fqdn', 'inet:email']
#             assert 'seen' in ioc
#             assert ioc['tags'] == []
#         assert 'id' in d_result['data']
#         assert 'removed' in d_result['data']
#         assert 'guid' in d_result['data']['id']
#
#     async def test_update_published(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
#         uctx = return_userctx()
#         mock = i_mock()
#         mock['content-type'] = 'X-IBM/Report-malware'
#         mock['tags'] = ['mal.wannacry', 'bhv.test']
#         mock['tufos'] = [{
#                     'type': 'inet:fqdn',
#                     'property': 'google.com'
#                 },
#                 {
#                     'type': 'inet:email',
#                     'property': 'test@ibm.com'
#                 }]
#         async with cortex_db:
#             rf_op = ReportFactory(logging.getLogger(__name__),
#                                   userctx=uctx,
#                                   db_node_history=db_node_history,
#                                   cortex_db=cortex_db)
#             i_result = await rf_op.ingest(mock)
#             assert(i_result['data']['id'])
#             f_result = await rf_op.fetch(i_result['data']['id'], mock=r_mock())
#             p_result = await rf_op.set_published(i_result['data']['id'])
#         assert i_result['msg'] == 'success'
#         assert i_result['status'] == 0
#         assert 'id' in i_result['data']
#         assert 'published' in i_result['data']
#         assert 'guid' in i_result['data']['id']
#         assert 'created' in f_result['data']
#         assert 'published' in f_result['data']
#         assert f_result['data']['content'] == 'test report content'
#         assert f_result['data']['content-type'] == 'x-ibm/report-malware'
#         assert f_result['data']['entitlement'] == 'premium'
#         assert f_result['data']['fileName'] == 'test0.md'
#         assert f_result['data']['primary_tag'] == 'mal.wannacry'
#         assert f_result['data']['summary'] == 'test0 summary'
#         assert f_result['data']['tags'].sort() == ['mal.wannacry', 'bhv.test'].sort() #should include malware family tags
#         assert f_result['data']['title'] == 'test0'
#         for ioc in f_result['data']['indicators']:
#             assert ioc['indicator'] in ['google.com', 'test@ibm.com']
#             assert ioc['type'] in ['inet:fqdn', 'inet:email']
#             assert 'seen' in ioc
#             assert ioc['tags'] == []
#         assert 'id' in p_result['data']
#         assert 'published' in p_result['data']
#         assert 'fileName' in p_result['data']
#
#     async def test_update_report(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
#         uctx = return_userctx()
#         mock = i_mock()
#         mock['content-type'] = 'X-IBM/Report-malware'
#         mock['tags'] = ['mal.wannacry', 'bhv.test']
#         mock['tufos'] = [{
#                     'type': 'inet:fqdn',
#                     'property': 'google.com'
#                 },
#                 {
#                     'type': 'inet:email',
#                     'property': 'test@ibm.com'
#                 }]
#         async with cortex_db:
#             rf_op = ReportFactory(logging.getLogger(__name__),
#                                   userctx=uctx,
#                                   db_node_history=db_node_history,
#                                   cortex_db=cortex_db)
#             i_result = await rf_op.ingest(mock)
#             assert(i_result['data']['id'])
#             mock['id'] = i_result['data']['id']
#             u_result = await rf_op.update_report(mock)
#         assert i_result['msg'] == 'success'
#         assert i_result['status'] == 0
#         assert 'id' in i_result['data']
#         assert 'published' in i_result['data']
#         assert 'guid' in i_result['data']['id']
#         assert u_result['msg'] == 'success'
#         assert u_result['status'] == 0
#         assert 'id' in u_result['data']
#         assert 'published' in u_result['data']
#         assert 'guid' in u_result['data']['id']
#
#     async def test_ingest_existing_report(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         db_node_history = DbNodeHistory(logging.getLogger(__name__), ArangoConfig())
#         uctx = return_userctx()
#         mock = i_mock()
#         mock['content-type'] = 'X-IBM/Report-malware'
#         mock['tags'] = ['mal.wannacry', 'bhv.test']
#         mock['tufos'] = [{
#                     'type': 'inet:fqdn',
#                     'property': 'google.com'
#                 },
#                 {
#                     'type': 'inet:email',
#                     'property': 'test@ibm.com'
#                 }]
#         async with cortex_db:
#             rf_op = ReportFactory(logging.getLogger(__name__),
#                                   userctx=uctx,
#                                   db_node_history=db_node_history,
#                                   cortex_db=cortex_db)
#             e_result = await rf_op.ingest(mock)
#             assert(e_result['data']['id'])
#             with pytest.raises(Exception):
#                 await rf_op.ingest(mock)
#
