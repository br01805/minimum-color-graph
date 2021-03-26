
import logging
import re
import pytest
from arango import ArangoClient
from libs.config import get_config, set_root_dir, set_profile, find_config_dir
from libs.userctx import UserContext
from src.libs.db_node_history import (DbNodeHistory, ArangoConfig, OperationType, OperationSource,
                                      HistoryNodeRec, NewNodeFormat, TagFormat, ConfigError, DbConnectError)


class ConfigTester:
    def __init__(self):
        self.cfgmap = {}
        self.cfgmap[ArangoConfig.N_HOST] = get_config('arango_host')
        self.cfgmap[ArangoConfig.N_PORT] = 8529
        self.cfgmap[ArangoConfig.N_DBNAME] = 'sherlock_production'
        self.cfgmap[ArangoConfig.N_ADMIN_USR] = 'root'
        self.cfgmap[ArangoConfig.N_ADMIN_PW] = 'admin_password'
        self.cfgmap[ArangoConfig.N_QUERY_USR] = 'audit_history'
        self.cfgmap[ArangoConfig.N_QUERY_PW] = 'query_password'
        self.cfgmap[ArangoConfig.N_HISTORY_COLNAME] = 'synapse_history_nodes'

    def get_config(self, name):
        return self.cfgmap[name]

    def set_config(self, name, value):
        self.cfgmap[name] = value


@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True


@pytest.fixture(scope='session')
def setup_database():
    cfg = ArangoConfig()
    db_client = ArangoClient(hosts='http://{}:{}'.format(cfg.hostname, cfg.port))
    audit_db = db_client.db(
        cfg.dbname, username=cfg.admin_user, password=cfg.admin_password)
    if audit_db.has_collection(cfg.history_nodes_colname):
        history_collection = audit_db.collection(cfg.history_nodes_colname)
        history_collection.truncate()
    return True


@pytest.fixture(scope='function')
def node_history():
    cfg = ArangoConfig()
    history_db = DbNodeHistory(logging.getLogger(__name__), cfg)
    yield history_db
    history_db.close()


@pytest.mark.usefixtures("setup_config")
class TestConfig:
    def test_arango_config(self):
        cfg = ArangoConfig()
        print(cfg)
        assert cfg.hostname == get_config('arango_host')
        assert cfg.port == 8529
        assert cfg.dbname == 'sherlock_test'
        assert cfg.admin_user == 'root'
        assert cfg.admin_password == 'BigInternet9!'
        assert cfg.query_user == 'audit_history'
        assert cfg.query_password == 'BigInternet9!'
        assert cfg.history_nodes_colname == 'synapse_history_nodes'

    def test_arango_config_port_negative(self):
        cfgtest = ConfigTester()
        cfgtest.set_config(ArangoConfig.N_PORT, -1)
        with pytest.raises(ConfigError):
            cfg = ArangoConfig(cfgtest.get_config)

    def test_arango_config_port_too_large(self):
        cfgtest = ConfigTester()
        cfgtest.set_config(ArangoConfig.N_PORT, 0xFFFF + 1)
        with pytest.raises(ConfigError):
            cfg = ArangoConfig(cfgtest.get_config)

    def test_arango_config_host_empty(self):
        cfgtest = ConfigTester()
        cfgtest.set_config(ArangoConfig.N_HOST, '')
        with pytest.raises(ConfigError):
            cfg = ArangoConfig(cfgtest.get_config)

    def test_arango_config_dbname_empty(self):
        cfgtest = ConfigTester()
        cfgtest.set_config(ArangoConfig.N_DBNAME, '')
        with pytest.raises(ConfigError):
            cfg = ArangoConfig(cfgtest.get_config)

    def test_arango_config_admin_user_empty(self):
        cfgtest = ConfigTester()
        cfgtest.set_config(ArangoConfig.N_ADMIN_USR, '')
        with pytest.raises(ConfigError):
            cfg = ArangoConfig(cfgtest.get_config)

    def test_arango_config_node_history_collection_name_empty(self):
        cfgtest = ConfigTester()
        cfgtest.set_config(ArangoConfig.N_HISTORY_COLNAME, '')
        with pytest.raises(ConfigError):
            cfg = ArangoConfig(cfgtest.get_config)


class TestAuditRec(object):
    def test_auditrec(self):
        nodeFormat = NewNodeFormat('inet:dns:a', 'www.example.com/10.1.1.1')
        nodeFormat.add_property('inet:fqdn', 'www.example.com')
        nodeFormat.add_property('inet:ipv4', '10.1.1.1')

        auditRec = HistoryNodeRec(user_id=10, login_name='joe@mydomain.com', op_type=OperationType.add_node,
                                  op_source=OperationSource.domain_tools,
                                  node_guid='112233445566778899aabbccddeeff117090eca958616f63b3b40600d1a06ba0',
                                  tufo_data=nodeFormat)
        assert auditRec.node_guid == '112233445566778899aabbccddeeff117090eca958616f63b3b40600d1a06ba0'
        assert auditRec.user_id == 10
        assert auditRec.op_type == OperationType.add_node
        assert auditRec.tstamp


@pytest.mark.usefixtures('setup_config')
class TestConnection:
    def test_connection_bad_admin_password(self):
        with pytest.raises(DbConnectError):
            cfg = ArangoConfig()
            cfg.admin_password = 'BadPassword'
            history_db = DbNodeHistory(logging.getLogger(__name__), cfg)
            history_db.connect_collection()

    def test_connection(self):
        cfg = ArangoConfig()
        history_db = DbNodeHistory(logging.getLogger(__name__), cfg)
        history_db.connect_collection()


@pytest.mark.usefixtures('setup_config', 'setup_database', 'node_history')
class TestNodeHistory:
    fqdn_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba0'
    ip_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba1'
    dns_a_guid_a = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba2'
    file_bytes_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba3'
    whois_guid1 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba4'
    hash_md5_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba5'
    hash_sha1_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba6'
    hash_sha256_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba7'
    hash_sha512_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba8'
    tag1_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06ba9'
    tag2_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06baa'
    storm_guid = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bab'
    ip_guid2 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bac'
    ip_guid3 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bad'

    whois_guid2 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bc0'
    whois_guid3 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bc1'
    whois_guid4 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bc2'
    whois_guid5 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bc3'
    whois_guid6 = '112233445566778899aabbccddeeff116090eca958616f63b3b40600d1a06bc4'

    def test_insert_fqdn(self, node_history):
        node_history.add_inet_fqdn(1000, 'joe@mydomain.com', OperationSource.simple,
                                   TestNodeHistory.fqdn_guid,
                                   'freedomains.net')
        search_nodes = node_history.find_by_guid(TestNodeHistory.fqdn_guid)

    def test_insert_ip_addr(self, node_history):
        result = node_history.add_inet_ip_addr(1000, 'joe@mydomain.com', OperationSource.simple,
                                               TestNodeHistory.ip_guid,
                                               '23.23.23.23')
        val = str(result)
        re_result = re.match(r'.+joe@mydomain.com.+OperationType.add_node.+OperationSource.simple.+ipv4.+23.23.23.23',
                             val)
        assert re_result

        result = node_history.add_inet_ip_addr(1000, 'joe@mydomain.com', OperationSource.simple,
                                               TestNodeHistory.ip_guid3,
                                               'fe80::e985:2178:c137:8a88')
        val = str(result)
        re_result = re.match(r'.+joe@mydomain.com.+OperationType.add_node.+OperationSource.simple.+ipv6.+fe80::e985:2178:c137:8a88',
                             val)
        assert re_result

        with pytest.raises(AssertionError):
            result = node_history.add_inet_ip_addr(1000, 'joe@mydomain.com', OperationSource.simple,
                                                   TestNodeHistory.ip_guid2,
                                                   '23')

    def test_insert_dns_a(self, node_history):
        node_format = NewNodeFormat('inet:dns:a', 'www.example.com/10.1.1.1')
        node_format.add_property('inet:dns:a:fqdn', 'www.example.com')
        node_format.add_property('inet:dns:a:ipv4', '10.1.1.1')

        guid_a = '112233445566778899aabbccddeeff112972617f1f68428b80412cb8747da200'
        audit_rec = HistoryNodeRec(1000, 'george@example.com', OperationType.add_node, OperationSource.bulk_import,
                                   guid_a,
                                   node_format)
        node_history.insert(audit_rec)

        guid_b = '112233445566778899aabbccddeeff112972617f1f68428b80412cb8747da201'
        rec1 = node_history.add_inet_dns_a(1001, 'bill@example.com', OperationSource.passive_total, guid_b,
                                           'www.example.com', '10.1.1.2')
        val = str(rec1)
        re_result = re.match(r'.+bill@example[.]com.+OperationType.add_node.+OperationSource.passive_total.+www.example.com/10.1.1.2',
                             val)
        assert re_result

    def test_insert_quoted_string(self, node_history):
        guid_b = '112233445566778899aabbccddeeff112972617f1f68428b80412cb8747da201'
        rec1 = node_history.add_dev_str(1001, 'bill@example.com', OperationSource.virus_total, guid_b,
                                        'hello "world"')
        val = str(rec1)
        re_result = re.match(r'.+bill@example[.]com.+2972617f1f68428b80412cb8747da201.+OperationType.add_node.+OperationSource.virus_total.+hello "world"',
                             val)
        assert re_result

    def test_insert_quoted_string(self, node_history):
        guid_b = '112233445566778899aabbccddeeff112972617f1f68428b80412cb8747da201'
        rec1 = node_history.add_dev_str(1001, 'bill@example.com', OperationSource.virus_total, guid_b,
                                        '你好大美丽的世界')
        val = str(rec1)
        re_result = re.match(r'.+bill@example[.]com.+2972617f1f68428b80412cb8747da201.+OperationType.add_node.+OperationSource.virus_total.+你好大美丽的世界',
                             val)
        assert re_result




    def test_insert_file_bytes(self, node_history):
        node_history.add_file_bytes(1000, 'joe@mydomain.com', OperationSource.simple,
                                    TestNodeHistory.file_bytes_guid,
                                    'myfilename.exe',
                                    'aa42b61dd644766a86a310a156064f98',
                                    '7e1c63dbec598a89cbf20a19f3903b8e2fec14b7',
                                    '43efc9cc0f306b9c9d81d33dc1701049749d696183eaf051cf90d92609a09d9b',
                                    '1b7d6e3ba7143e2834d3dd89105bba3e0ebb46838ba955e4a2a145e422426515d89e6834aedeef46f44b367d65405c52a542ce88afa3066e4586521b09860fb8',
                                    'application/pdf')

    def test_insert_whois(self, node_history):
        node_history.add_whois_contact(1000, 'joe@mydomain.com', OperationSource.simple,
                                       TestNodeHistory.whois_guid1, 'george@somedomain.com')
        node_history.add_whois_rar(1000, 'joe@mydomain.com', OperationSource.simple,
                                   TestNodeHistory.whois_guid2, 'george@somedomain.com')
        node_history.add_whois_rec(1000, 'joe@mydomain.com', OperationSource.simple,
                                   TestNodeHistory.whois_guid3, 'ns1.example.com')
        node_history.add_whois_recns(1000, 'joe@mydomain.com', OperationSource.simple,
                                     TestNodeHistory.whois_guid4, 'george@somedomain.com')
        node_history.add_whois_reg(1000, 'joe@mydomain.com', OperationSource.simple,
                                   TestNodeHistory.whois_guid5, 'george@somedomain.com')
        node_history.add_whois_regmail(1000, 'joe@mydomain.com', OperationSource.simple,
                                       TestNodeHistory.whois_guid6, 'george@somedomain.com', 'www.example.com')

    def test_insert_file_hashes(self, node_history):
        result = node_history.add_file_hash_md5(1000, 'joe@mydomain.com', OperationSource.simple,
                                                TestNodeHistory.hash_md5_guid,
                                                'aa42b61dd644766a86a310a156064f98')
        assert re.match(
            '.+joe@mydomain[.]com.+md5.+aa42b61dd644766a86a310a156064f98', str(result))

        result = node_history.add_file_hash_sha1(1000, 'joe@mydomain.com', OperationSource.simple,
                                                 TestNodeHistory.hash_sha1_guid,
                                                 'bd2f1d59f162d5a75586800be1ccd53457932bcf')
        assert re.match('.+joe@mydomain[.]com.+sha1.+bd2f1d59f162d5a75586800be1ccd53457932bcf',
                        str(result))

        result = node_history.add_file_hash_sha256(1000, 'joe@mydomain.com', OperationSource.simple,
                                                   TestNodeHistory.hash_sha256_guid,
                                                   '43efc9cc0f306b9c9d81d33dc1701049749d696183eaf051cf90d92609a09d9b')
        assert re.match('.+joe@mydomain[.]com.+sha256.+43efc9cc0f306b9c9d81d33dc1701049749d696183eaf051cf90d92609a09d9b',
                        str(result))

        result = node_history.add_file_hash_sha512(1000, 'joe@mydomain.com', OperationSource.simple,
                                                   TestNodeHistory.hash_sha512_guid,
                                                   '1b7d6e3ba7143e2834d3dd89105bba3e0ebb46838ba955e4a2a145e422426515d89e6834aedeef46f44b367d65405c52a542ce88afa3066e4586521b09860fb8')
        assert re.match('.+joe@mydomain[.]com.+sha512.+1b7d6e3ba7143e2834d3dd89105bba3e0ebb46838ba955e4a2a145e422426515d89e6834aedeef46f44b367d65405c52a542ce88afa3066e4586521b09860fb8',
                        str(result))

    def test_tags(self, node_history):
        node_history.add_tag(1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.tag1_guid,
                             'int.tag1', 'New title', 'New doc')
        node_history.add_tag(1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.tag2_guid,
                             'int.tag2', 'New title', 'New doc')
        node_history.modify_tag(1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.tag1_guid,
                                'Update title', 'Update doc')

        result = node_history.apply_node_tag(1000, 'joe@mydomain.com', OperationSource.domain_tools,
                                             TestNodeHistory.fqdn_guid, 'int.tag1')
        assert result.op_source == OperationSource.domain_tools
        assert result.op_type == OperationType.apply_tag
        assert result.tufo_data.tufo_tags == ['int.tag1']
        result = node_history.apply_node_tag(1000, 'joe@mydomain.com', OperationSource.virus_total,
                                             TestNodeHistory.fqdn_guid, ['int.tag1', 'int.tag2'])
        assert result.tufo_data.tufo_tags == ['int.tag1', 'int.tag2']

        result = node_history.apply_node_tag(1000, 'joe@mydomain.com', OperationSource.virus_total,
                                             TestNodeHistory.fqdn_guid, [])
        assert not result

        result = node_history.apply_node_tag(1000, 'joe@mydomain.com', OperationSource.virus_total,
                                             TestNodeHistory.fqdn_guid, '')
        assert not result

        node_history.remove_node_tag(1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.fqdn_guid,
                                     'int.tag2')
        node_history.delete_node(
            1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.tag1_guid)

        node_history.delete_tag(1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.tag1_guid,
                                'int.tag1', [TestNodeHistory.fqdn_guid])

    def test_set_properties(self, node_history):
        node_history.add_inet_ip_addr(1000, 'joe@mydomain.com', OperationSource.simple, TestNodeHistory.ip_guid2,
                                      '24.24.24.24')
        node_history.set_properties(1000, 'joe@mydomain.com', OperationSource.passive_total, TestNodeHistory.ip_guid2,
                                    (('inet:ipv4:cc', 'us'),
                                     ('inet:ipv4:asn', '19969'),
                                     ('inet:ipv4:type', 'private')
                                     ))
        search_result = node_history.find_by_guid(TestNodeHistory.ip_guid2)
        assert (search_result)
        assert len(search_result) == 2
        assert int(search_result[0]['userId']) == 1000
        assert search_result[0]['loginName'] == 'joe@mydomain.com'
        assert search_result[0]['guid'] == TestNodeHistory.ip_guid2
        assert search_result[0]['opType'] == OperationType.add_node.name
        assert search_result[0]['opSource'] == OperationSource.simple.name
        assert search_result[1]['guid'] == TestNodeHistory.ip_guid2
        assert search_result[1]['opType'] == str(OperationType.set_property.name)

    def test_log_add(self, node_history):
        userctx = UserContext(1000, 'joe@mydomain.com', '', OperationSource.simple)
        created_rec = ('node', (('file:bytes', 'guid:e7ffc308789389cdbf5bb4a1b83e4140'),
                                {'iden': '40ae6902a7df9c62b06a7a9dce9cb763c1807c21163000aaa4e58793dee8c820',
                                 'tags': {'mal': (None, None),
                                          'mal.dropper': (None, None),
                                          'mal.dropper.titanbot': (None, None)},
                                 'props': {'mime': 'application/pdf',
                                           '.created': 1572372517331,
                                           'name': 'helloworld.pdf',
                                           'md5': '920e19faf259c1a474d3bb4e5e00c321',
                                           'sha1': 'd2a24162a712a190cc71dea888ec19cf35019b9c',
                                           'sha256': 'ab1bda5b748790703430341db2380bf1b3b5390588549265ff2a516bbcd4e9e0'},
                                 'tagprops': {'mal.dropper.titanbot': {'confidence': 90}},
                                 'path': {'nodes': ('40ae6902a7df9c62b06a7a9dce9cb763c1807c21163000aaa4e58793dee8c820',)}}))
        node_history.log_add(userctx,  '112233445566778899aabbccddeeff11a38896599301a2738fba7f0b87844b1f', created_rec)
        search_result = node_history.find_by_guid('112233445566778899aabbccddeeff11a38896599301a2738fba7f0b87844b1f')
        assert (search_result)
        assert len(search_result) == 1
        assert int(search_result[0]['userId']) == 1000
        assert search_result[0]['loginName'] == 'joe@mydomain.com'
        assert search_result[0]['guid'] == '112233445566778899aabbccddeeff11a38896599301a2738fba7f0b87844b1f'
        assert search_result[0]['opType'] == OperationType.add_node.name
        assert search_result[0]['opSource'] == OperationSource.simple.name

    def test_log_add_funcs(self, node_history):
        userctx = UserContext(1000, 'joe@mydomain.com', 'txid-1', OperationSource.simple)
        result = node_history.add_inet_url(
            *userctx.dbnh_values(),
            '1000000000000000000000000000000000000000000000000000000000000000',
            'http://www.example.com/index.php')
        assert result

        result = node_history.add_inet_urlredir(
            *userctx.dbnh_values(),
            '1000000000000000000000000000000000000000000000000000000000000001',
            'http://www.example.com/index.php', 'http://www.landingpage.com/')
        assert result

    def test_invalid_guid(self, node_history):
        with pytest.raises(Exception, match=r"GUID"):
            node_history.find_by_guid('invalid')
