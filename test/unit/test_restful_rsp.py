import pytest
from libs.restful_format import restful_format_singular

class TestRestfulResponse():

    def test_ipv4(self):
        """ Test REST'ful IPv4"""
        ipv4 = ('node',
                (('inet:ipv4', 168427778),
                 {'iden': '6812a8f53fec224cc4f5d47bae4e18b6b81f96db7157db94bc818fdc9b893aa2',
                  'tags': {
                      'trend': (None, None),
                      'trend.lifecycle': (None, None),
                      'trend.lifecycle.exeobj': (1513641600000, 1550188800000),
                      'thr': (None, None),
                      'thr.c2c': (None, None)
                  },
                  'props': {
                      'type': 'private',
                      'asn': 0,
                      'loc': '??',
                      '.created': 1568325369489
                  },
                  'tagprops': {},
                  'path': {'nodes': ('841f99175b815abbc39cffc91bcbd2f52d8f8c5b8df3e114d4117f8d4069adad',)}
                  }
                 ))
        restfuldata_singular = restful_format_singular(ipv4)
        expected_obj = {'guid': '6812a8f53fec224cc4f5d47bae4e18b6b81f96db7157db94bc818fdc9b893aa2',
                           'nodedata': [],
                        'type': 'inet:ipv4',
                        'property': '10.10.1.2',
                        'created': '2019-09-12T21:56:09Z',
                        'secondary_property': {
                            'type': 'private',
                            'asn': 0,
                            'loc': '??'
                        },
                        'tags': {
                            '#thr.c2c': (None, None),
                            '#trend.lifecycle.exeobj': ('2017-12-19T00:00:00Z', '2019-02-15T00:00:00Z')
                        },
                        'tag_tree': {
                            '#thr': (None, None),
                            '#trend': (None, None),
                            '#trend.lifecycle': (None, None)
                        },
                        'tagprops': None,
                        'pivot_path': {
                            'nodes': ('841f99175b815abbc39cffc91bcbd2f52d8f8c5b8df3e114d4117f8d4069adad',)
                        },
                        'category': 'attribution'
                       }
        assert restfuldata_singular == expected_obj

    def test_dns_a(self):
        dns = ('node', (('inet:dns:a', ('nytunion.com', 1170440520)),
                        {'iden': '51dee39dfe353a83facded0e597838576f591c1e1af98a9b6617276e5e4b7623',
                         'tags': {
                             'int': (None, None),
                             'int.capsource': (None, None),
                             'int.capsource.pt': (1537979989000, 1537979989001)
                         },
                         'props': {
                             '.created': 1565140460636,
                             '.seen': (1467933493000, 1499521069000),
                             'fqdn': 'nytunion.com',
                             'ipv4': 1170440520
                         },
                         'path': {'nodes': ('51dee39dfe353a83facded0e597838576f591c1e1af98a9b6617276e5e4b7623',)}
                        }))

        restfuldata_singular = restful_format_singular(dns)
        expected_result = {'guid': '51dee39dfe353a83facded0e597838576f591c1e1af98a9b6617276e5e4b7623',
                           'nodedata': [],
                           'type': 'inet:dns:a',
                           'property': '(nytunion.com, 69.195.129.72)',
                           'created': '2019-08-07T01:14:20Z',
                           'secondary_property': {
                               'fqdn': 'nytunion.com',
                               'ipv4': '69.195.129.72',
                               'seen': ('2016-07-07T23:18:13Z', '2017-07-08T13:37:49Z')
                           },
                           'tags': {
                               '#int.capsource.pt': ('2018-09-26T16:39:49Z', '2018-09-26T16:39:49Z')
                           },
                           'tag_tree': {
                               '#int': (None, None),
                               '#int.capsource': (None, None)
                           },
                           'tagprops': None,
                           'pivot_path': {
                               'nodes': ('51dee39dfe353a83facded0e597838576f591c1e1af98a9b6617276e5e4b7623',)
                           },
                           'category': 'none'
                          }

        assert restfuldata_singular == expected_result

    def test_tcp4(self):
        tcp4 = ('node', (
            ('inet:server', 'tcp://1.1.1.1:8080'), {
                'iden': '841f99175b815abbc39cffc91bcbd2f52d8f8c5b8df3e114d4117f8d4069adad',
                'tags': {
                    'code': (None, None),
                    'code.exeobj': (None, None)
                },
                'props': {
                    'proto': 'tcp',
                    'port': 8080,
                    'ipv4': 16843009,
                    '.created': 1568656968074
                },
                'tagprops': {},
                'path': {
                    'nodes': ('841f99175b815abbc39cffc91bcbd2f52d8f8c5b8df3e114d4117f8d4069adad',)
                }
             })
            )

        restfuldata_singular = restful_format_singular(tcp4)
        expected_result = {'guid': '841f99175b815abbc39cffc91bcbd2f52d8f8c5b8df3e114d4117f8d4069adad',
                           'nodedata': [],
                          'type': 'inet:server',
                          'property': 'tcp://1.1.1.1:8080',
                          'created': '2019-09-16T18:02:48Z',
                          'secondary_property': {
                              'proto': 'tcp',
                              'port': 8080,
                              'ipv4': '1.1.1.1'
                          },
                          'tags': {
                              '#code.exeobj': (None, None)
                          },
                          'tag_tree': {
                              '#code': (None, None)
                          },
                          'tagprops': None,
                          'pivot_path': {'nodes': ('841f99175b815abbc39cffc91bcbd2f52d8f8c5b8df3e114d4117f8d4069adad',)},
                          'category': 'context'
                         }
        assert restfuldata_singular == expected_result

    def test_urlfile_comp(self):
        urlfile = ('node',
                   (('inet:urlfile', ('https://twitter.com/oguzpamuk/status/1160905143593910272?s=20', 'guid:e7ffc308789389cdbf5bb4a1b83e4140')),
                    {'iden': '185e2db18f01bc9c3cf5288daafde221c919a798c70f8950746312feae1d5c05',
                     'tags': {},
                     'props': {'url': 'https://twitter.com/oguzpamuk/status/1160905143593910272?s=20',
                               'file': 'guid:e7ffc308789389cdbf5bb4a1b83e4140',
                               '.created': 1571254390894
                               },
                     'tagprops': {},
                     'path': {'nodes': ('185e2db18f01bc9c3cf5288daafde221c919a798c70f8950746312feae1d5c05',)}
                     }))
        result = restful_format_singular(urlfile)
        expected_result = {'guid': '185e2db18f01bc9c3cf5288daafde221c919a798c70f8950746312feae1d5c05',
                           'nodedata': [],
                           'type': 'inet:urlfile',
                           'property': '("https://twitter.com/oguzpamuk/status/1160905143593910272?s=20", guid:e7ffc308789389cdbf5bb4a1b83e4140)',
                           'created': '2019-10-16T19:33:10Z',
                           'secondary_property': {
                               'url': 'https://twitter.com/oguzpamuk/status/1160905143593910272?s=20',
                               'file': 'guid:e7ffc308789389cdbf5bb4a1b83e4140'
                           },
                           'tags': {},
                           'tag_tree': {},
                           'tagprops': None,
                           'pivot_path': {'nodes': ('185e2db18f01bc9c3cf5288daafde221c919a798c70f8950746312feae1d5c05',)},
                           'category': 'none'
                          }
        assert result == expected_result

    def test_file_bytes(self):
        filebytes = ('node',
                     (('file:bytes', 'sha256:00033b5b33b59ad88aa4f196c08eb7a6d2e6ab181ec729e8ed577d55f8b1f3ee'),
                      {'iden': '49006199a4116c5facca74f6f48d296a6e6b4ccc7318380b3d5662c59eea0ea1',
                       'tags': {'bhv': (None, None),
                                'bhv.aka': (None, None),
                                'bhv.aka.paloalto': (None, None),
                                'bhv.aka.paloalto.mal': (None, None),
                                'bhv.aka.paloalto.mal.mirai': (None, None),
                                'bhv.aka.vt': (None, None),
                                'bhv.aka.vt.tag': (None, None),
                                'bhv.aka.vt.tag.elf': (None, None),
                                'bookmark': (None, None),
                                'int': (None, None),
                                'int.capsource': (None, None),
                                'int.capsource.vt': (1546799761000, 1546799761001),
                                'int.detection': (None, None),
                                'int.detection.vt': (None, None),
                                'int.detection.vt.positives': (None, None),
                                'int.detection.vt.positives.36': (1553863416000, 1553863416001),
                                'mal': (None, None),
                                'mal.gen': (None, None)},
                       'props': {'.created': 1565139725995,
                                 'md5': '60a775f4a99420644181d1ddbd2d6d1d',
                                 'mime': 'application/octet-stream',
                                 'name': 'clean.m68k',
                                 'sha1': 'cf3ef5c92d8636e1ede0c90f5163149f7320a57f',
                                 'sha256': '00033b5b33b59ad88aa4f196c08eb7a6d2e6ab181ec729e8ed577d55f8b1f3ee',
                                 'sha512': '47fac68072680e08e63b70e020e0bdff42424092d32809fc1f15e63acce2ce53fc6d950604a3d9c62a4508c9596dbb7bc8462ab40241a2eb5fbefcb8d4dc0e13',
                                 'size': 168192},
                       'path': {'nodes': ('49006199a4116c5facca74f6f48d296a6e6b4ccc7318380b3d5662c59eea0ea1',)}
                       }))
        result = restful_format_singular(filebytes)
        expected_result = {'guid': '49006199a4116c5facca74f6f48d296a6e6b4ccc7318380b3d5662c59eea0ea1',
                           'nodedata': [],
                           'type': 'file:bytes',
                           'property': 'sha256:00033b5b33b59ad88aa4f196c08eb7a6d2e6ab181ec729e8ed577d55f8b1f3ee',
                           'created': '2019-08-07T01:02:05Z',
                           'secondary_property': {
                               'md5': '60a775f4a99420644181d1ddbd2d6d1d',
                               'mime': 'application/octet-stream',
                               'name': 'clean.m68k',
                               'sha1': 'cf3ef5c92d8636e1ede0c90f5163149f7320a57f',
                               'sha256': '00033b5b33b59ad88aa4f196c08eb7a6d2e6ab181ec729e8ed577d55f8b1f3ee',
                               'sha512': '47fac68072680e08e63b70e020e0bdff42424092d32809fc1f15e63acce2ce53fc6d950604a3d9c62a4508c9596dbb7bc8462ab40241a2eb5fbefcb8d4dc0e13',
                               'size': 168192
                           },
                           'tags': {'#bhv.aka.paloalto.mal.mirai': (None, None),
                                    '#bhv.aka.vt.tag.elf': (None, None),
                                    '#bookmark': (None, None),
                                    '#int.capsource.vt': ('2019-01-06T18:36:01Z', '2019-01-06T18:36:01Z'),
                                    '#int.detection.vt.positives.36': ('2019-03-29T12:43:36Z', '2019-03-29T12:43:36Z'),
                                    '#mal.gen': (None, None)},
                           'tag_tree': {'#bhv': (None, None),
                                        '#bhv.aka': (None, None),
                                        '#bhv.aka.paloalto': (None, None),
                                        '#bhv.aka.paloalto.mal': (None, None),
                                        '#bhv.aka.vt': (None, None),
                                        '#bhv.aka.vt.tag': (None, None),
                                        '#int': (None, None),
                                        '#int.capsource': (None, None),
                                        '#int.detection': (None, None),
                                        '#int.detection.vt': (None, None),
                                        '#int.detection.vt.positives': (None, None),
                                        '#mal': (None, None)},
                           'tagprops': None,
                           'pivot_path': {'nodes': ('49006199a4116c5facca74f6f48d296a6e6b4ccc7318380b3d5662c59eea0ea1',)},
                           'category': 'malicious'}
        assert result == expected_result

    def test_digraph_edge(self):
        edge = ('node',
                (('edge:refs', (('file:bytes', 'guid:e7ffc308789389cdbf5bb4a1b83e4140'), ('inet:ipv4', 33686018))),
                 {'iden': '9ab1064d8228759f4ad2c7905cddc869e2c41a81fbe046d88dcdeb3439993375',
                  'tags': {},
                  'props': {
                      'n1': ('file:bytes', 'guid:e7ffc308789389cdbf5bb4a1b83e4140'),
                      'n1:form': 'file:bytes',
                      'n2': ('inet:ipv4', 33686018),
                      'n2:form': 'inet:ipv4',
                      '.created': 1568662040067
                  },
                  'tagprops': {},
                  'path': {'nodes': ('9ab1064d8228759f4ad2c7905cddc869e2c41a81fbe046d88dcdeb3439993375',)}
                 }))
        result = restful_format_singular(edge)
        expected_result = {'guid': '9ab1064d8228759f4ad2c7905cddc869e2c41a81fbe046d88dcdeb3439993375',
                           'nodedata': [],
                           'type': 'edge:refs',
                           'property': '(file:bytes=guid:e7ffc308789389cdbf5bb4a1b83e4140, inet:ipv4=2.2.2.2)',
                           'created': '2019-09-16T19:27:20Z',
                           'secondary_property': {
                               'n1': ('file:bytes', 'guid:e7ffc308789389cdbf5bb4a1b83e4140'),
                               'n1:form': 'file:bytes',
                               'n2': ('inet:ipv4', '2.2.2.2'),
                               'n2:form': 'inet:ipv4'},
                           'tags': {},
                           'tag_tree': {},
                           'tagprops': None,
                           'pivot_path': {'nodes': ('9ab1064d8228759f4ad2c7905cddc869e2c41a81fbe046d88dcdeb3439993375',)},
                           'category': 'none'
                          }
        assert result == expected_result

    def test_whois_contact(self):
        contact = ('node',
                   (('inet:whois:contact', (('www.example.com', 1517875200000), 'admin')),
                    {'iden': '5dfc92c669d422bf47121069eb91250e52b9d7b7f692495e9f040d6605bc8078',
                     'tags': {},
                     'props': {
                         'rec': ('www.example.com', 1517875200000),
                         'rec:fqdn': 'www.example.com',
                         'rec:asof': 1517875200000,
                         'type': 'admin',
                         '.created': 1575510817796
                     },
                     'tagprops': {},
                     'path': {'nodes': ('5dfc92c669d422bf47121069eb91250e52b9d7b7f692495e9f040d6605bc8078',)}
                    }
                   ))
        result = restful_format_singular(contact)
        expected_result = {'guid': '5dfc92c669d422bf47121069eb91250e52b9d7b7f692495e9f040d6605bc8078',
                           'nodedata': [],
                           'type': 'inet:whois:contact',
                           'property': "(('www.example.com', '2018-02-06T00:00:00Z'), admin)",
                           'created': '2019-12-05T01:53:37Z',
                           'secondary_property': {
                               'rec': ('www.example.com', '2018-02-06T00:00:00Z'),
                               'rec:fqdn': 'www.example.com',
                               'rec:asof': '2018-02-06T00:00:00Z',
                               'type': 'admin'
                           },
                           'tags': {},
                           'tag_tree': {},
                           'tagprops': None,
                           'pivot_path': {'nodes': ('5dfc92c669d422bf47121069eb91250e52b9d7b7f692495e9f040d6605bc8078',)},
                           'category': 'none'}
        assert expected_result == result

    def test_whois_recns(self):
        recns = ('node',
                 (('inet:whois:recns', ('ns1.google.com', ('www.example.com', 1517875200000))),
                  {'iden': '4320dba9200d7280e34f7c28278b45ffa3df3c98213f02c2a2b44bb64a511b52',
                   'tags': {},
                   'props': {
                       'ns': 'ns1.google.com',
                       'rec': ('www.example.com', 1517875200000),
                       'rec:fqdn': 'www.example.com',
                       'rec:asof': 1517875200000,
                       '.created': 1575515613866
                   },
                   'tagprops': {},
                   'path': {'nodes': ('4320dba9200d7280e34f7c28278b45ffa3df3c98213f02c2a2b44bb64a511b52',)}
                   }))
        result = restful_format_singular(recns)
        expected_result = {'guid': '4320dba9200d7280e34f7c28278b45ffa3df3c98213f02c2a2b44bb64a511b52',
                           'nodedata': [],
                           'type': 'inet:whois:recns',
                           'property': '(ns1.google.com, www.example.com=2018-02-06T00:00:00Z)',
                           'created': '2019-12-05T03:13:33Z',
                           'secondary_property': {
                               'ns': 'ns1.google.com',
                               'rec': ('www.example.com', '2018-02-06T00:00:00Z'),
                               'rec:fqdn': 'www.example.com',
                               'rec:asof': '2018-02-06T00:00:00Z'
                           },
                           'tags': {},
                           'tag_tree': {},
                           'tagprops': None,
                           'pivot_path': {'nodes': ('4320dba9200d7280e34f7c28278b45ffa3df3c98213f02c2a2b44bb64a511b52',)},
                           'category': 'none'}
        assert expected_result == result


    def test_x509_cert(self):
        cert = ('node', (('crypto:x509:cert', '6e23cad0d132f53245eea002a65da6de'),
                         {'iden': 'fa904f5676b52929ae3b5045e58f17a4837267c4a483f82c9abf11d8922bf83b',
                          'tags': {},
                          'props': {
                              '.created': 1579291306862,
                              'subject': 'CN=albytools.ru/OU=Domain Control Validated',
                              'issuer': 'CN=COMODO RSA Domain Validation Secure Server CA/C=GB/L=Salford'
                                        '/ST=Greater Manchester/O=COMODO CA Limited',
                              'serial': '178402460556229622426920996450216245778',
                              'version': 2,
                              'validity:notbefore': 1522540800000, 'validity:notafter': 1554076800000,
                              'ext:sans': (('dns', 'albytools.ru'), ('dns', 'www.albytools.ru'), ('ip', '18.18.18.18')),
                              'identities:fqdns': ('www.example.com',), 'identities:emails': ('george@example.com',),
                              'identities:ipv4s': (286331153, 303174162),
                              'identities:ipv6s': ('fe80::282f:cc41:15f0:f915',),
                              'identities:urls': ('http://www.example.com/index.php',)
                          },
                          'tagprops': {},
                          'path': {'nodes': ('472cd4e4a65a347fbe10a2492761194eec28e751a09095c36b30810899a3a42a',
                                             'fa904f5676b52929ae3b5045e58f17a4837267c4a483f82c9abf11d8922bf83b')}
                         }
                        ))
        result = restful_format_singular(cert)
        expected_result = {'guid': 'fa904f5676b52929ae3b5045e58f17a4837267c4a483f82c9abf11d8922bf83b',
                           'nodedata': [],
                           'type': 'crypto:x509:cert',
                           'property': '6e23cad0d132f53245eea002a65da6de',
                           'created': '2020-01-17T20:01:46Z',
                           'secondary_property': {
                               'subject': 'CN=albytools.ru/OU=Domain Control Validated',
                               'issuer': 'CN=COMODO RSA Domain Validation Secure Server CA/C=GB/L=Salford'
                                         '/ST=Greater Manchester/O=COMODO CA Limited',
                               'serial': '178402460556229622426920996450216245778',
                               'version': 2,
                               'validity:notbefore': '2018-04-01T00:00:00Z',
                               'validity:notafter': '2019-04-01T00:00:00Z',
                               'ext:sans': (('dns', 'albytools.ru'), ('dns', 'www.albytools.ru'), ('ip', '18.18.18.18')),
                               'identities:fqdns': ('www.example.com',),
                               'identities:emails': ('george@example.com',),
                               'identities:ipv4s': ('17.17.17.17', '18.18.18.18'),
                               'identities:ipv6s': ('fe80::282f:cc41:15f0:f915',),
                               'identities:urls': ('http://www.example.com/index.php',)
                           },
                           'tags': {},
                           'tag_tree': {},
                           'tagprops': None,
                           'pivot_path': {
                               'nodes': ('472cd4e4a65a347fbe10a2492761194eec28e751a09095c36b30810899a3a42a',
                                         'fa904f5676b52929ae3b5045e58f17a4837267c4a483f82c9abf11d8922bf83b')},
                           'category': 'none'}
        assert expected_result == result

