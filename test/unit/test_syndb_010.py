import pytest
import logging
import os
import shutil
import tempfile
import contextlib
import ipaddress
import socket
import struct

import hashlib
import synapse.lib.msgpack as s_msgpack

from libs.config import set_root_dir, set_profile, find_config_dir, get_config
import helpers.quoted_storm_value as qsv
from helpers.http_errors import SynapseError
from src.libs.cortex_db import CortexDb, read_async
import synapse.telepath as s_telepath
import synapse.exc as s_exc

"""
A node is Synapse 010 appears as:
('node', (('inet:ipv4', 168427777),
          {'iden':     '86c28e645cef94a2edd8d7726e1857ef104165ce907a206005b0cd527af65b6c',
           'tags':     {'trend': (None, None),
                        'trend.lifecycle': (None, None),
                        'trend.lifecycle.exeobj': (1513641600000, 1550188800000)},
           'props':    {'type': 'private',
                        'asn': 0,
                        'loc': '??',
                        '.created': 1568314832206},
           'tagprops': {},
           'path':     {}
           }))
"""

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@contextlib.contextmanager
def create_temp_dir(chdir=False):
    tempdir = tempfile.mkdtemp()
    curd = os.getcwd()

    try:
        dstpath = tempdir
        if chdir:
            os.chdir(dstpath)
        yield dstpath

    finally:
        if chdir:
            os.chdir(curd)
        shutil.rmtree(tempdir, ignore_errors=True)

def get_cortex_url():
    url = 'tcp://{}:{}@{}:{}/'.format(
        get_config('cortex_user'),
        get_config('cortex_password'),
        get_config('cortex_host'),
        get_config('cortex_port'))
    return url


def remote_cortex_running():
    return False

@pytest.mark.usefixtures("setup_config")
class TestNewSynapse:
    async def add_ip_addrs(self, syndb, count):
        """Add a list of IP addresses to database"""
        base = int(ipaddress.ip_address('10.10.1.1'))

        new_addrs = '['
        for i in range(count):
            new_addrs += 'inet:ipv4={} '.format(ipaddress.ip_address(base + i).__str__())
        new_addrs += ' +#thr.c2c.quackbot=(2017/12/19, 2019/02/15) +#code.exedropper]'
        res = await read_async(None, syndb, new_addrs)
        return res

    def get_filebytes_guid(self, node_list):
        node = list(filter(lambda x: x[0] == 'node', node_list))
        str_guid = node[0][1][0][1];
        guid = str_guid[5:] if str_guid.startswith('guid:') else str_guid
        return guid

    def get_form_value(self, node_list):
        node = list(filter(lambda x: x[0] == 'node', node_list))
        form = node[0][1][0]
        if form[0].endswith(':ipv4'):
            valu =  socket.inet_ntoa(struct.pack("!I", int(form[1])))
        else:
            valu = form[1]
        return valu


    async def addEdgeRefs(self, syndb, filebytes, ipv4):
        fb_guid = self.get_filebytes_guid(filebytes)
        ipv4 = self.get_form_value(ipv4)
        edge_query = f'[ edge:refs=((file:bytes, guid:{fb_guid}), (inet:ipv4, {ipv4})) ]'
        res = await read_async(None, syndb, edge_query)
        return list(filter(lambda x: x[0] == 'node', res))


    @pytest.mark.skipif(not remote_cortex_running(), reason='Remote cortex not running')
    @pytest.mark.asyncio
    async def test_basic_telepath_ask(self):
        """Test context manager SynapseDB connection"""
        url = get_cortex_url()
        ask_query = 'inet:ipv4 | limit 10'
        ask_query = 'inet:dns:a=(nytunion.com,69.195.129.72)'
        try:
            async with await s_telepath.openurl(url) as proxy:
                ask_results = await read_async(None, proxy, ask_query)
                for node in ask_results:
                    print(node)
        except s_exc.SynErr as syn_err:
            print(syn_err)

    @pytest.mark.asyncio
    async def test_basic_ask(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        ask_query = 'inet:ipv4 | limit 10'
        async with cortex_db.connect_yield() as syndb:
            ip_addr_results = await self.add_ip_addrs(syndb, 10)
            assert ip_addr_results
            ask_results = await read_async(logger, syndb, ask_query)
            for node in ask_results:
                assert node[0] == 'node' or node[0] == 'print'

    @pytest.mark.asyncio
    async def test_basic_ask_recursive(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        ask_query = 'inet:ipv4 | limit 10'
        async with cortex_db:
            ip_addr_results = await self.add_ip_addrs(cortex_db.conn(), 10)
            ask_results = await read_async(logger, cortex_db.conn(), ask_query)
            ipval_start = -1
            ipval_total = 0
            for node in ask_results:
                if node[0] == 'node':
                    if ipval_start < 0:
                        ipval_start = node[1][0][1]
                    assert node[1][0][1] - ipval_start == ipval_total
                    ipval_total += 1

    @pytest.mark.asyncio
    async def test_query_by_guid(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        ask_query = 'inet:ipv4 | limit 10'
        async with cortex_db:
            ip_addr_results = await self.add_ip_addrs(cortex_db.conn(), 1)
            ask_results = await read_async(logger, cortex_db.conn(), ask_query)
            guids_to_query = []
            for node in ask_results:
                if node[0] == 'node':
                    guids_to_query.append(node[1][1]['iden'])
            for guid in guids_to_query:
                ask_results = await read_async(logger, cortex_db.conn(), 'iden {}'.format(guid))
                tufo_nodes = list(filter(lambda node: node[0] == 'node', ask_results))
                assert tufo_nodes[0][0] == 'node'
                assert isinstance(tufo_nodes[0][1][0], tuple)
                assert len(tufo_nodes[0][1][0]) == 2
                assert tufo_nodes[0][1][0][0] == 'inet:ipv4'
                assert tufo_nodes[0][1][1]['iden'] == guid

    @pytest.mark.asyncio
    async def test_set_props(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        ask_query = 'inet:ipv4 | limit 10'
        async with cortex_db:
            ask_results = await read_async(logger, cortex_db.conn(), '[ inet:ipv4=1.1.1.1 ]')
            guids_to_query = []
            for node in ask_results:
                if node[0] == 'node':
                    guids_to_query.append(node[1][1]['iden'])
            for guid in guids_to_query:
                syn_query = 'iden {} | [ +#int.test :asn=123 ]'.format(guid)
                ask_results = await read_async(logger, cortex_db.conn(), syn_query)
                tufo_nodes = list(filter(lambda node: node[0] == 'node', ask_results))
                assert tufo_nodes[0][0] == 'node'
                assert isinstance(tufo_nodes[0][1][0], tuple)
                assert len(tufo_nodes[0][1][0]) == 2
                assert tufo_nodes[0][1][0][0] == 'inet:ipv4'
                assert tufo_nodes[0][1][1]['iden'] == guid
                assert tufo_nodes[0][1][1]['tags'] == {'int': (None, None), 'int.test': (None, None)}


    @pytest.mark.asyncio
    async def test_ask_no_result(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        ask_query = '#thr.badtag'
        async with cortex_db:
            ask_results = await read_async(logger, cortex_db.conn(), ask_query)
            assert not ask_results

    @pytest.mark.asyncio
    async def test_ask_bad_syntax(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        ask_query = 'dfjajkfd'
        with pytest.raises(SynapseError) as excinfo:
            async with cortex_db:
                ask_results = await read_async(logger, cortex_db.conn(), ask_query)

    @pytest.mark.asyncio
    async def test_duplicate_add(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            ask_results = await read_async(None, cortex_db.conn(), '[inet:ipv4=1.1.1.1]')
            assert len(ask_results) == 2
            assert ask_results[1][1][0][0] == 'inet:ipv4'
            assert ask_results[1][1][0][1] == 16843009
            ask_results2 = await read_async(logger, cortex_db.conn(), '[inet:ipv4=1.1.1.1]')
            assert len(ask_results2) == 1
            assert ask_results2[0][0] == 'node'
            assert ask_results2[0][1][0][0] == 'inet:ipv4'

    @pytest.mark.asyncio
    async def test_apply_tag_node_missing(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            ask_results = await read_async(logger, cortex_db.conn(), 'inet:ipv4=1.1.1.1 [+#thr.c2c.quackbot]')
            assert not ask_results

    @pytest.mark.asyncio
    async def test_tcp4(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            ask_results = await read_async(logger, syndb, '[inet:server=1.1.1.1:8080 +#code.exeobj]')

    @pytest.mark.asyncio
    async def test_add_dnsa(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            inet_dns_a = '(www.example.com,23.23.23.23)'
            query = '[inet:dns:a={}]'.format(inet_dns_a)
            ask_results = await read_async(logger, syndb, query)
            assert ask_results

    @pytest.mark.asyncio
    async def test_add_dnsa_vars(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            fqdn = 'www.example.com'
            ip_addr = '23.23.23.23'
            opts = {'vars': {'fqdn': fqdn, 'ipv4': ip_addr}}
            query = '[inet:dns:a=($fqdn, $ipv4)]'
            ask_results = await read_async(logger, syndb, query, opts=opts)
            assert ask_results

    @pytest.mark.asyncio
    async def test_add_dnsa_vars2(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            fqdn = 'www.example.com'
            ip_addr = '23.23.23.23'
            opts = {'vars': {'inet_dns_a': (fqdn, ip_addr)}}
            query = '[inet:dns:a=$inet_dns_a]'
            ask_results = await read_async(logger, syndb, query, opts=opts)
            assert ask_results

    @pytest.mark.asyncio
    async def test_add_dnsa_vars3(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            #inet_dns_a = '(www.example.com, 23.23.23.23)'
            dns_a_str = 'inet:dns:a=("www.example.com", "23.23.23.23")'
            synname, synvalue = qsv.parse_name_value(dns_a_str)
            opts = {'vars': {'inet_dns_a': synvalue}}
            query = '[inet:dns:a=$inet_dns_a]'
            ask_results = await read_async(logger, syndb, query, opts=opts)
            assert ask_results

    @pytest.mark.asyncio
    async def test_filebytes(self):

        """
        ('node', (('file:bytes', 'guid:e7ffc308789389cdbf5bb4a1b83e4140'),
                  {'iden': '40ae6902a7df9c62b06a7a9dce9cb763c1807c21163000aaa4e58793dee8c820', 'tags': {},
                   'props': {'mime': 'application/pdf', '.created': 1568402648154, 'name': 'helloworld.pdf'},
                   'tagprops': {'mal.dropper.titanbot': {'confidence': 90}}
                   'path': {'nodes': ('40ae6902a7df9c62b06a7a9dce9cb763c1807c21163000aaa4e58793dee8c820',)}}))

        """
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            name = 'HelloWorld.pdf'
            file_data = [chr(c) for c in range(ord('0'), ord('a'))]
            file_data_str = ''.join(file_data).encode('utf8')
            ipv4_results = await read_async(logger, syndb, '[ inet:ipv4=2.2.2.2 :asn=444 ]')
            md5 = hashlib.md5(file_data_str).hexdigest()
            sha1 = hashlib.sha1(file_data_str).hexdigest()
            sha256 = hashlib.sha256(file_data_str).hexdigest()
            opts = {'vars': {'bytes': file_data,
                             'filename': name,
                             'md5': md5, 'sha1': sha1, 'sha256': sha256,
                             'pe_compiled': 1431312336000}}
            ask_results = await syndb.addTagProp('confidence', ('int', {}), {'doc': 'my tag confidence score'})
            fb_results = await read_async(logger, syndb,
                                          f'[ file:bytes=$bytes :name=$filename :mime=application/pdf'
                                          f' :md5=$md5 :sha1=$sha1 :sha256=$sha256 :mime:pe:compiled=$pe_compiled'
                                          f' +#mal.dropper.titanbot:confidence=90 ]',
                                          opts)
            for node in fb_results:
                if node[0] == 'node':
                    assert node[1][0][0] == 'file:bytes'
                elif node[0] == 'node:add':
                    assert len(node[1]['ndef']) == 2
                    assert node[1]['ndef'][0] in ('file:bytes', 'file:mime', 'file:base', 'file:ismime', 'syn:tag',
                                                  'hash:md5', 'hash:sha1', 'hash:sha256')
                    if not isinstance(node[1]['ndef'][1], tuple):
                        assert node[1]['ndef'][1].startswith('guid:') \
                               or node[1]['ndef'][1] in ('??', 'helloworld.pdf', 'application/pdf',
                                                         'mal.dropper.titanbot', 'mal.dropper', 'mal',
                                                         '920e19faf259c1a474d3bb4e5e00c321',
                                                         'd2a24162a712a190cc71dea888ec19cf35019b9c',
                                                         'ab1bda5b748790703430341db2380bf1b3b5390588549265ff2a516bbcd4e9e0')
            edge_result = await self.addEdgeRefs(syndb, fb_results, ipv4_results)
            assert len(edge_result) == 1
            assert edge_result[0][1][0][0] == 'edge:refs'

    @pytest.mark.asyncio
    async def test_iden_hash(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            ask_results = await read_async(logger, syndb, '[ inet:ipv4 = 9.9.9.9 ]')
            filtered_node = list(filter(lambda x: x[0] == 'node', ask_results))
            found_node = filtered_node[0] if filtered_node else None
            print(found_node[1][1]['iden'])
        byts2 = s_msgpack.en((found_node[1][0][0], found_node[1][0][1]))
        iden2 = hashlib.sha256(byts2).hexdigest()
        print(iden2)

    @pytest.mark.asyncio
    async def test_iden_hash(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            ask_results = await read_async(logger, syndb, '[ inet:ipv4 = 9.9.9.9 ]')
            filtered_node = list(filter(lambda x: x[0] == 'node', ask_results))
            found_node = filtered_node[0] if filtered_node else None
            print(found_node[1][1]['iden'])

        byts2 = s_msgpack.en((found_node[1][0][0], found_node[1][0][1]))
        iden2 = hashlib.sha256(byts2).hexdigest()
        print(iden2)

    @pytest.mark.asyncio
    async def test_geo_place(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            opts = {'vars': {'guid': 'f7ffc308789389cdbf5bb4a1b83e4140',
                             'name': '/na/us/dallas',
                             'desc': 'description',
                             'loc': 'us',
                             'addr': '1111 Happy Ln, Dallas, TX, 10000',
                             'latlong': (32.77815, -96.7954),
                             'rad': '1000 km',
                             }}
            geo_results = await read_async(
                logger, syndb,
                '[ geo:place=$guid :name=$name :desc=$desc :loc=$loc :address=$addr :latlong=$latlong :radius=$rad]',
                opts)
            assert geo_results


    @pytest.mark.asyncio
    async def test_whois_contact(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            opts = {'vars': {'fqdn': 'www.example.com',
                             'asof': '2018-02-06T00:00:00Z',
                             'type': 'admin',
                             }}
            contact = await read_async(
                logger, syndb,
                '[ inet:whois:contact=(($fqdn, $asof), $type)]',
                opts)
            assert contact

    @pytest.mark.asyncio
    async def test_whois_recns(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            opts = {'vars': {'fqdn': 'www.example.com',
                             'asof': '2018-02-06T00:00:00Z',
                             'server': 'ns1.google.com',
                             }}
            recns = await read_async(
                logger, syndb,
                '[ inet:whois:recns=($server, ($fqdn, $asof))]',
                opts)
            assert recns

    @pytest.mark.asyncio
    async def test_urlredir(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            opts = {'vars': {'url1': 'http://www.example.com/index.html',
                             'url2': 'https://www.landingpage.com/index.html',
                             }}
            urlredir = await read_async(
                logger, syndb,
                '[ inet:urlredir=($url1, $url2) ]',
                opts)
            assert urlredir

    @pytest.mark.asyncio
    async def test_tag_dates(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            opts = {'vars': {'ip1': '192.192.192.192',
                             'ip2': '10.10.10.10',
                             }}
            ipaddrs = await read_async(
                logger, syndb,
                '[ inet:ipv4=$ip1 inet:ipv4=$ip2 ]',
                opts)
            assert ipaddrs

            ip1 = await read_async(
                logger, syndb,
                'inet:ipv4=$ip1 [+#bhv.tor=(2016/01/01, 2016/12/01)]',
                opts)
            assert ip1

            ip2 = await read_async(
                logger, syndb,
                'inet:ipv4=$ip2 [+#bhv.tor=2019/01/01]',
                opts)
            assert ip2

    @pytest.mark.asyncio
    async def test_x509(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger)
        async with cortex_db.connect_yield() as syndb:
            opts = {'vars': {'subject': 'CN=albytools.ru/OU=Domain Control Validated',
                             'issuer': 'CN=COMODO RSA Domain Validation Secure Server CA/C=GB/L=Salford/ST=Greater Manchester/O=COMODO CA Limited',
                             'serial': '178402460556229622426920996450216245778',
                             'version': '2',
                             'notbefore': '2018/04/01',
                             'notafter': '2019/04/01',
                             'md5': '',
                             'sha1': 'a4bf1ebe09871ebbdaeaf648d99516b0954f9ebd',
                             'sha256': '',
                             'rsa_key': '',
                             'algo': '',
                             'signature': '',
                             'ext_sans': (('dns', 'albytools.ru'), ('dns', 'www.albytools.ru'), ('ip', '18.18.18.18')),
                             'ext_crls': '',
                             'ident_fqdns': ['www.example.com'],
                             'ident_emails': ['george@example.com'],
                             'ident_ipv4': ['17.17.17.17', '18.18.18.18'],
                             'ident_ipv6': ['fe80::282f:cc41:15f0:f915'],
                             'ident_urls': ['http://www.example.com/index.php'],
                             'crl_urls': []
                             }}
            cert = await read_async(
                logger, syndb,
                '[ crypto:x509:cert="*" :subject=$subject :issuer=$issuer :serial=$serial :version=$version '
                ':validity:notbefore=$notbefore :validity:notafter=$notafter '
                ':ext:sans=$ext_sans :identities:fqdns=$ident_fqdns :identities:emails=$ident_emails '
                ':identities:ipv4s=$ident_ipv4 :identities:ipv6s=$ident_ipv6 :identities:urls=$ident_urls]',
                opts)
            assert cert

            ipaddr = await read_async(
                logger, syndb,
                'inet:ipv4=17.17.17.17 | tee { -+> * } { <- * }')
            assert ipaddr

