import pytest
import json
from tornado.httputil import HTTPHeaders

from libs.config import set_root_dir, set_profile, find_config_dir
from libs.userctx import OperationSource, UserContext

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

class FakeRequest:
    def __init__(self, user_id, login_name, txid, extra_headers=None):
        the_headers =  { 'X-User': json.dumps({ 'userId': user_id,
                                                'email': login_name }),
                         'X-TransactionId': txid }
        self.headers = HTTPHeaders(the_headers)
        if extra_headers:
            for name, value in extra_headers.items():
                self.headers.add(name, value)

class MissingHeadersRequest:
    def __init__(self):
        self.headers =  HTTPHeaders()

@pytest.mark.usefixtures("setup_config")
class TestUserContext:
    def test_create_header(self):
        http_req = FakeRequest(1000, 'george@example.com', '0AXB9V5GUdg8m4om10jCMeUr')
        result = UserContext.from_http_req(http_req, OperationSource.simple)
        assert result.login_name == 'george@example.com'
        assert result.user_id == 1000
        assert result.txid == '0AXB9V5GUdg8m4om10jCMeUr'

        assert result.dbnh_params() == {'userId': 1000, 'email': 'george@example.com',
                                        'op_source': OperationSource.simple}
        assert result.email == 'george@example.com'
        assert result.op_source == OperationSource.simple

        for (name, value) in sorted(result.get_headers().get_all()):
            if name == 'X-User':
                assert value == '{"userId": 1000, "email": "george@example.com"}'
            elif name == 'X-Transactionid':
                assert value == '0AXB9V5GUdg8m4om10jCMeUr'

    def test_create_header_dhn(self):
        http_req = FakeRequest(1000, 'george@example.com', '0AXB9V5GUdg8m4om10jCMeUr',
                               {'X-Slack-Email': 'bill@example.com'})
        result = UserContext.from_http_req(http_req, OperationSource.simple, http_req.headers['X-Slack-Email'])
        assert result.login_name == 'bill@example.com'
        assert result.user_id == 0
        assert result.txid == '0AXB9V5GUdg8m4om10jCMeUr'

        assert result.dbnh_params() == {'userId': 0, 'email': 'bill@example.com', 'op_source': OperationSource.simple}
        assert result.email == 'bill@example.com'

        new_object = result.clone_op_src(OperationSource.domain_tools)
        assert new_object.dbnh_params() == {'userId': 0, 'email': 'bill@example.com', 'op_source': OperationSource.domain_tools}


    def test_empty_headers(self):
        http_req = MissingHeadersRequest()
        result = UserContext.from_http_req(http_req, OperationSource.ibm_quad9)
        assert result.login_name == ''
        assert result.user_id == 0
        assert result.txid == None
        assert result.op_source == OperationSource.ibm_quad9

        assert result.email == 'nobody@ibm.com'
