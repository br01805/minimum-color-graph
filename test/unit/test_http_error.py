import pytest
from helpers.http_errors import (HttpError, ParameterError, ResourceMissingError, ConstraintError,
                                 ResourceExistsError, InvalidSynapseProperties, InvalidSynapseProperty,
                                 RelationshipSynapseError)
from http import HTTPStatus


class TestHttpErrror:
    def test_http_error(self):
        err = HttpError(HTTPStatus.BAD_REQUEST, 'failure', -1000)
        assert err.rsp_code == HTTPStatus.BAD_REQUEST
        assert err.status_msg == 'failure'
        assert err.status_code == -1000
        msg = str(err)
        assert msg

    def test_http_parameter_error(self):
        err = ParameterError('foo', 'Missing name key', -1100)
        assert err.rsp_code == HTTPStatus.BAD_REQUEST
        assert err.status_msg == 'parameter_error'
        assert err.status_code == -1100
        msg = str(err)
        assert msg

    def test_http_resource_missing(self):
        err = ResourceMissingError('foo', -1200)
        assert err.rsp_code == HTTPStatus.GONE
        assert err.status_msg == 'missing_resource'
        assert err.status_code == -1200
        msg = str(err)
        assert msg

    def test_http_resource_missing_tuple(self):
        err = ResourceMissingError(('inet:ipv4', '9.9.9.9'), -1200)
        assert err.rsp_code == HTTPStatus.GONE
        assert err.status_msg == 'missing_resource'
        assert err.status_code == -1200
        msg = str(err)
        assert msg.find('inet:ipv4=9.9.9.9') >= 0

    def test_http_resource_exists(self):
        err = ResourceExistsError('foo')
        assert err.rsp_code == HTTPStatus.CONFLICT
        assert err.status_msg == 'duplicate_resource'
        assert err.status_code == 1
        msg = str(err)
        assert msg

    def test_http_resource_exists(self):
        err = ResourceExistsError(('inet:url', 'http://www.example.com/index.php'))
        assert err.rsp_code == HTTPStatus.CONFLICT
        assert err.status_msg == 'duplicate_resource'
        assert err.status_code == 1
        msg = str(err)
        assert msg.find('inet:url="http://www.example.com/index.php"') >= 0

    def test_http_constraint(self):
        err = ConstraintError('foo', 'Has children', -1400)
        assert err.rsp_code == HTTPStatus.BAD_REQUEST
        assert err.status_msg == 'operation_constraint'
        assert err.status_code == -1400
        msg = str(err)
        assert msg

    def test_invalid_properties(self):
        err = InvalidSynapseProperties(('prop1', 'prop2'), -1500)
        assert err.rsp_code == HTTPStatus.BAD_REQUEST
        assert err.status_msg == 'invalid_synapse_properties'
        assert err.status_code == -1500
        msg = str(err)
        assert msg

    def test_invalid_property(self):
        err = InvalidSynapseProperty('prop1', -1600)
        assert err.rsp_code == HTTPStatus.BAD_REQUEST
        assert err.status_msg == 'invalid_synapse_property'
        assert err.status_code == -1600
        msg = str(err)
        assert msg

    def test_relationship_synapse(self):
        err = RelationshipSynapseError(('parent', 'valu1'), ('child', 'value2'), -1600)
        assert err.rsp_code == HTTPStatus.BAD_REQUEST
        assert err.status_msg == 'relationship_failure'
        assert err.status_code == -1600
        msg = str(err)
        assert msg

    def function_bravo(self):
        raise ResourceExistsError('inet:ipv4=23.23.23.23')

    def function_alpha(self):
        self.function_bravo()
        return True

    def test_relationship_synapse(self):
        try:
            self.function_bravo()
        except HttpError as err:
            assert err.rsp_code == 409

