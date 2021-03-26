import helpers.synform_utils as su

class TestSynFormUtils:
    def test_extract_url(self):
        result = su.extract_uri_fqdn('inet:url', 'https://www.example.com/index.php')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == 'inet:fqdn'
        assert result[1] == 'www.example.com'

        result = su.extract_uri_fqdn('inet:url', 'https://1.1.1.1/index.php')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == 'inet:ipv4'
        assert result[1] == '1.1.1.1'

        result = su.extract_uri_fqdn('inet:url', 'https://[2001:db8:3:4::192.0.2.33]/index.php')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == 'inet:ipv6'
        assert result[1] == '2001:db8:3:4::192.0.2.33'

    def test_extract_fqdn(self):
        result = su.extract_uri_fqdn('inet:fqdn', 'www.example.com')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == 'inet:fqdn'
        assert result[1] == 'www.example.com'

    def test_extract_ipv4(self):
        result = su.extract_uri_fqdn('inet:ipv4', '9.9.9.9')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == 'inet:ipv4'
        assert result[1] == '9.9.9.9'

    def test_missing_fqdn(self):
        result = su.extract_uri_fqdn('inet:url', 'file://localhost/foo/bar')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] == 'inet:url'
        assert result[1] == 'file://localhost/foo/bar'

    def test_has_fqdn(self):
        assert su.has_fqdn('inet:url', 'https://www.example.com/index.php')
        assert su.has_fqdn('inet:fqdn', 'www.example.com')
        assert not su.has_fqdn('inet:url', 'https://1.1.1.1/index.php')
        assert not su.has_fqdn('inet:url', 'https://[2001:db8:3:4::192.0.2.33]/index.php')

    def test_has_ipaddr(self):
        assert su.has_ipaddr('inet:ipv4', '1.1.1.1')
        assert su.has_ipaddr('inet:ipv6', '2001:db8:3:4::192.0.2.33')
        assert su.has_ipaddr('inet:url', 'https://1.1.1.1/index.php')
        assert su.has_ipaddr('inet:url', 'https://[2001:db8:3:4::192.0.2.33]/index.php')
        assert not su.has_ipaddr('inet:url', 'https://www.example.com/index.php')
