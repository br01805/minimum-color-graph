from helpers.url_authority import get_url_authority
class TestAuthority:
    def test_fqdn(self):
        result = get_url_authority('http://www.example.com:80/index.php')
        assert result[0] == 'inet:fqdn' and result[1] == 'example.com'

    def test_ipv4(self):
        result = get_url_authority('http://1.1.1.1/index.php')
        assert result[0] == 'inet:ipv4' and result[1] == '1.1.1.1'

    def test_ipv6(self):
        result = get_url_authority('http://[fe80::6958:5e61:c52b:f4b1]/index.php')
        assert result[0] == 'inet:ipv6' and result[1] == 'fe80::6958:5e61:c52b:f4b1'

        result = get_url_authority('http://[fe80::6958:5e61:c52b:f4b1]:80/index.php')
        assert result[0] == 'inet:ipv6' and result[1] == 'fe80::6958:5e61:c52b:f4b1'

    def test_bad_url(self):
        result = get_url_authority('http://')
        assert result is None

        result = get_url_authority('1.1.1.1')
        assert result is None

        result = get_url_authority('junk')
        assert result is None
