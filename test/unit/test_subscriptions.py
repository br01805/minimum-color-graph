
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
        self.cfgmap[ArangoConfig.N_HOST] = 'localhost'
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

@pytest.mark.usefixtures('setup_config', 'setup_database', 'node_history')
def add_test_user(node_history):
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


@pytest.mark.usefixtures('setup_config', 'setup_database', 'node_history')
class TestNodeHistory:
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

    def add_test_user(self, node_history):
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
