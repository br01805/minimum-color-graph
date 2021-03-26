import pytest

from libs.convert_ip import (convert_ip, convert_ip_singular)

class TestIpConvert:
    """Test IP address conversion."""

    def test_convert_ip(self):
        """Test converting IPv4 addresses."""
        ipv4 = [
            [
                '1b60796dc25c527170718ea858114f6b',
                {
                    'inet:ipv4': 134744072,
                    'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                    'tufo:form': 'inet:ipv4',
                    'inet:ipv4:cc': 'us',
                    'node:created': 1543006559273,
                    'inet:ipv4:asn': 15169,
                    'inet:ipv4:type': '??'
                }
            ]
        ]
        ipv4data = convert_ip(ipv4)
        assert ipv4data == [
            [
                '1b60796dc25c527170718ea858114f6b',
                {
                    'inet:ipv4': '8.8.8.8',
                    'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                    'tufo:form': 'inet:ipv4',
                    'inet:ipv4:cc': 'us',
                    'node:created': 1543006559273,
                    'inet:ipv4:asn': 15169,
                    'inet:ipv4:type': '??'
                }
            ]
        ]

    def test_convert_dns(self):
        dnsa = [
            [
                '9122622b31b9280fb11ef19d1fc37638',
                {
                    'node:ndef': 'ac66755752ba677e2c16ad6cdfe8cc62',
                    'tufo:form': 'inet:dns:a',
                    'inet:dns:a': 'www.2bunny.com/8.8.8.8',
                    'node:created': 1505244231299,
                    'inet:dns:a:fqdn': 'www.2bunny.com',
                    'inet:dns:a:ipv4': 134744072,
                    'inet:dns:a:seen:max': 1490659200000,
                    'inet:dns:a:seen:min': 1470417823000,
                    '#int.capsource.pt': 1505245316000
                }
            ]
        ]
        dnsadata = convert_ip(dnsa)
        assert dnsadata == [
            [
                '9122622b31b9280fb11ef19d1fc37638',
                {
                    'node:ndef': 'ac66755752ba677e2c16ad6cdfe8cc62',
                    'tufo:form': 'inet:dns:a',
                    'inet:dns:a': 'www.2bunny.com/8.8.8.8',
                    'node:created': 1505244231299,
                    'inet:dns:a:fqdn': 'www.2bunny.com',
                    'inet:dns:a:ipv4': '8.8.8.8',
                    'inet:dns:a:seen:max': 1490659200000,
                    'inet:dns:a:seen:min': 1470417823000,
                    '#int.capsource.pt': 1505245316000
                }
            ]
        ]

    def test_convert_tcp4(self):
        tcp = [
            [
                'e76b84518203a21cab4e91f69421619b',
                {
                    'inet:tcp4': 194042360569744,
                    'node:ndef': '43c76fe6277b2f858cbdebf270224c78',
                    'tufo:form': 'inet:tcp4',
                    'node:created': 1504023999704,
                    'inet:tcp4:ipv4': 2960851449,
                    'inet:tcp4:port': 8080
                }
            ]
        ]
        tcpdata = convert_ip(tcp)
        assert tcpdata == [
            [
                'e76b84518203a21cab4e91f69421619b',
                {
                    'inet:tcp4': '176.123.1.249:8080',
                    'node:ndef': '43c76fe6277b2f858cbdebf270224c78',
                    'tufo:form': 'inet:tcp4',
                    'node:created': 1504023999704,
                    'inet:tcp4:ipv4': '176.123.1.249',
                    'inet:tcp4:port': 8080
                }
            ]
        ]

    def test_dnsa_singular(self):
        dnsa_singular = [
            '9122622b31b9280fb11ef19d1fc37638',
            {
                'node:ndef': 'ac66755752ba677e2c16ad6cdfe8cc62',
                'tufo:form': 'inet:dns:a',
                'inet:dns:a': 'www.2bunny.com/8.8.8.8',
                'node:created': 1505244231299,
                'inet:dns:a:fqdn': 'www.2bunny.com',
                'inet:dns:a:ipv4': 134744072,
                'inet:dns:a:seen:max': 1490659200000,
                'inet:dns:a:seen:min': 1470417823000,
                '#int.capsource.pt': 1505245316000
            }
        ]
        dnsadata_singular = convert_ip_singular(dnsa_singular)
        assert dnsadata_singular == [
            '9122622b31b9280fb11ef19d1fc37638',
            {
                'node:ndef': 'ac66755752ba677e2c16ad6cdfe8cc62',
                'tufo:form': 'inet:dns:a',
                'inet:dns:a': 'www.2bunny.com/8.8.8.8',
                'node:created': 1505244231299,
                'inet:dns:a:fqdn': 'www.2bunny.com',
                'inet:dns:a:ipv4': '8.8.8.8',
                'inet:dns:a:seen:max': 1490659200000,
                'inet:dns:a:seen:min': 1470417823000,
                '#int.capsource.pt': 1505245316000
            }
        ]

    def test_ip_singular(self):
        ipv4_singular = [
            '1b60796dc25c527170718ea858114f6b',
            {
                'inet:ipv4': 134744072,
                'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                'tufo:form': 'inet:ipv4',
                'inet:ipv4:cc': 'us',
                'node:created': 1543006559273,
                'inet:ipv4:asn': 15169,
                'inet:ipv4:type': '??'
            }
        ]

        ipv4data_singular = convert_ip_singular(ipv4_singular)

        assert ipv4data_singular == [
            '1b60796dc25c527170718ea858114f6b',
            {
                'inet:ipv4': '8.8.8.8',
                'node:ndef': '6f8b9d293904771fd6da8ce28a4a51b9',
                'tufo:form': 'inet:ipv4',
                'inet:ipv4:cc': 'us',
                'node:created': 1543006559273,
                'inet:ipv4:asn': 15169,
                'inet:ipv4:type': '??'
            }
        ]

    def test_tcp_singular(self):
        tcp_singular = [
            'e76b84518203a21cab4e91f69421619b',
            {
                'inet:tcp4': 194042360569744,
                'node:ndef': '43c76fe6277b2f858cbdebf270224c78',
                'tufo:form': 'inet:tcp4',
                'node:created': 1504023999704,
                'inet:tcp4:ipv4': 2960851449,
                'inet:tcp4:port': 8080
            }
        ]
        tcpdata_singular = convert_ip_singular(tcp_singular)
        assert tcpdata_singular == [
            'e76b84518203a21cab4e91f69421619b',
            {
                'inet:tcp4': '176.123.1.249:8080',
                'node:ndef': '43c76fe6277b2f858cbdebf270224c78',
                'tufo:form': 'inet:tcp4',
                'node:created': 1504023999704,
                'inet:tcp4:ipv4': '176.123.1.249',
                'inet:tcp4:port': 8080
            }
        ]
