import logging
import pytest
import time
import datetime
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async
from libs.synapse_models.evil_feeds import EvilFeed
from libs.synapse_nodes import Tufo
from helpers.http_errors import ResourceMissingError, HttpError


@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True


async def add_nodes(cortex_db, ioc_type, max_num, add=None, remove=None):
    n_list = []
    current_time = time.strftime('%m-%d-%YZ', time.gmtime())
    d_tags = ['mal.wannacry', 'pwn.test',
              'code.test', 'tgt.test',
              'bookmark.test', 'review.test',
              'int.test', 'thr.test',
              'bhv.test', 'trend.test']
    op_type = {
        'domain': add_domain_nodes,
        'hash': add_hash_nodes,
        'ip': add_ip_nodes,
    }
    n_list = await op_type[ioc_type](cortex_db, max_num)
    forms = flat([]).get(ioc_type)
    await modify_tags(cortex_db, forms, d_tags, op='add')

    if remove:
        for items in remove:
            n_forms = flat(items[0]).get('custom')
            await modify_tags(cortex_db, n_forms, items[1], op='remove')

    if add:
        for items in add:
            n_forms = flat(items[0]).get('custom')
            await modify_tags(cortex_db, n_forms, items[1], op='add')

    return (n_list, current_time)


async def add_domain_nodes(cortex_db, max_num):
    d_list = []
    domain = 'domain.com'
    syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
    for num in range(1, max_num + 1):
        d_insrt = str(num) + domain
        await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                      (('inet:fqdn', d_insrt),))
        d_list.append(d_insrt)
    return d_list


async def add_ip_nodes(cortex_db, max_num):
    i_list = []
    syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
    for num in range(1, max_num + 1):
        i_insrt = '{0}.{0}.{0}.{0}'.format(str(num))
        await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                      (('inet:ipv4', i_insrt),))
        i_list.append(i_insrt)
    return i_list


async def add_hash_nodes(cortex_db, max_num):
    h_list = []
    hashs = '06be00b6796ea13a38950d3da1b5dee'
    syn_tufo = Tufo(logging.getLogger(__name__), cortex_db)
    for num in range(1, max_num + 1):
        h_insrt = str(num) + hashs
        await syn_tufo.add_test_nodes(None, cortex_db.conn(),
                                      (('hash:md5', h_insrt),))
        h_list.append(h_insrt)
    return h_list


async def modify_tags(cortex_db, forms, tags, op):
    new_string = ''
    for tag in tags:
        new_string += '+#%s ' % tag if op == 'add' else '-#%s ' % tag
    await read_async(None, cortex_db.conn(), '{} [{}]'.format(forms, new_string))

def flat(c_list=None):
    def flatten(l): return [item for sublist in l for item in sublist]
    hashes = ['hash:md5', 'hash:sha1', 'hash:sha256', 'hash:sha512']
    ips = ['inet:ipv4', 'inet:ipv6']
    domains = ['inet:fqdn', 'inet:url']
    return {
        'all': ' '.join(flatten([domains, hashes, ips])),
        'hash': ' '.join(flatten([hashes])),
        'domain': ' '.join(flatten([domains])),
        'ip': ' '.join(flatten([ips])),
        'custom': ' '.join(flatten([c_list])),
    }


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_config")
class TestEvilDomainFeed:
    async def test_domain_public(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            add1 = (['inet:fqdn=6domain.com', 'inet:fqdn=7domain.com'], [
                    'bhv.aka.test.mal', 'int.capdest.ibm.trustar.covid19'])
            add2 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly', 'int.tlp.irisonly'])
            add3 = (['inet:fqdn=9domain.com'], ['int.tlp.red', 'int.tlp.amber'])
            add4 = (['inet:fqdn=10domain.com'], ['omit.legit'])
            remove1 = (['inet:fqdn=com', 'inet:fqdn=6domain.com',
                        'inet:fqdn=7domain.com'], ['mal'])
            add = (add1, add2, add3, add4)
            remove = (remove1,)
            d_list, c_time = await add_nodes(cortex_db, 'domain', 10, add, remove)
            feed = EvilFeed(logging.getLogger(__name__),
                            'domain', cortex_db=cortex_db)
            result, cursor = await feed.run(limit=1000)
        assert isinstance(result, dict)
        assert len(result) == 8  # There are 11 total nodes, we remove Com node
        for node in d_list:
            if int(node.split('d')[0]) in [8, 9, 10]:
                assert node not in result.keys()  # Checking specific nodes are not included
            elif int(node.split('d')[0]) in [6, 7]:
                assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                assert sorted(['#bhv.aka.test.mal', '#thr.test', '#bhv.test',
                        '#trend.test', '#int.capdest.ibm.trustar.covid19']) == sorted(result[node]['tags'])
                assert result[node]['firstSeen'] == c_time
            else:
                assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                assert sorted(['#mal.wannacry', '#thr.test', '#bhv.test',
                        '#trend.test']) == sorted(result[node]['tags'])
                assert result[node]['firstSeen'] == c_time
        assert cursor == ''

    async def test_domain_private(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            add1 = (['inet:fqdn=6domain.com', 'inet:fqdn=7domain.com'], [
                    'bhv.aka.test.mal'])
            add2 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly', 'int.tlp.irisonly'])
            add3 = (['inet:fqdn=9domain.com'], ['int.tlp.red', 'int.tlp.amber'])
            add4 = (['inet:fqdn=10domain.com'], ['omit.legit'])
            remove1 = (['inet:fqdn=com', 'inet:fqdn=6domain.com',
                        'inet:fqdn=7domain.com'], ['mal'])
            add = (add1, add2, add3, add4)
            remove = (remove1,)
            d_list, c_time = await add_nodes(cortex_db, 'domain', 10, add, remove)
            feed = EvilFeed(logging.getLogger(__name__),
                            'domain', cortex_db=cortex_db)
            result, cursor = await feed.run(limit=1000, is_private=True)
        assert isinstance(result, dict)
        # There are 11 total nodes, we remove Com node
        assert len(result) == 11
        for node in d_list:
            if int(node.split('d')[0]) in [8, 9, 10]:
                assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                assert result[node]['firstSeen'] == c_time
                if node == '8domain.com':
                    assert sorted(['#int.tlp.ibmonly', '#thr.test', '#bhv.test',
                                   '#trend.test', '#pwn.test', '#int.tlp.irisonly',
                                   '#tgt.test', '#int.test', '#mal.wannacry']) == sorted(result[node]['tags'])
                elif node == '9domain.com':
                    assert sorted(['#int.tlp.red', '#thr.test', '#bhv.test',
                                   '#trend.test', '#pwn.test', '#int.tlp.amber',
                                   '#tgt.test', '#int.test', '#mal.wannacry']) == sorted(result[node]['tags'])
                elif node == '10domain.com':
                    assert sorted(['#omit.legit', '#thr.test', '#bhv.test',
                                   '#trend.test', '#pwn.test',
                                   '#tgt.test', '#int.test', '#mal.wannacry']) == sorted(result[node]['tags'])
            elif int(node.split('d')[0]) in [6, 7]:
                assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                assert sorted(['#bhv.aka.test.mal', '#thr.test', '#bhv.test',
                               '#trend.test', '#pwn.test',
                               '#tgt.test', '#int.test']) == sorted(result[node]['tags'])
                assert result[node]['firstSeen'] == c_time
            else:
                assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                assert sorted(['#bhv.test',
                               '#int.test',
                               '#mal.wannacry',
                               '#pwn.test',
                               '#tgt.test',
                               '#thr.test',
                               '#trend.test']) == sorted(result[node]['tags'])
                assert result[node]['firstSeen'] == c_time
        assert cursor == ''


@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestEvilIPFeed:
    async def test_ip_public(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            add1 = (['inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'],
                    ['bhv.aka.test.mal'])
            add2 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
            add3 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
            add4 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
            remove1 = (['inet:ipv4=11.11.11.11',
                        'inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'], ['mal'])
            add = (add1, add2, add3, add4)
            remove = (remove1,)
            i_list, c_time = await add_nodes(cortex_db, 'ip', 11, add, remove)
            feed = EvilFeed(logging.getLogger(__name__),
                            'ip', cortex_db=cortex_db)
            result, cursor = await feed.run(limit=1000)
            assert isinstance(result, dict)
            # There are 11 total nodes, we completely remove 11.11.11.11
            assert len(result) == 8
            for node in i_list:
                if int(node.split('.')[0]) in [8, 9, 10]:
                    assert node not in result.keys()  # Checking specific nodes are not included
                elif int(node.split('.')[0]) in [6, 7]:
                    assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                    assert sorted(['#bhv.aka.test.mal', '#bhv.test', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
                    assert result[node]['firstSeen'] == c_time
                else:
                    assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                    # assert sorted(['#bhv.test', '#mal.wannacry', '#thr.test', '#trend.test']) ==
                    assert '#bhv.test' in sorted(result[node]['tags'])
                    # assert '#mal.wannacry' in sorted(result[node]['tags'])
                    assert '#thr.test' in sorted(result[node]['tags'])
                    assert '#trend.test' in sorted(result[node]['tags'])
                    assert result[node]['firstSeen'] == c_time
            assert cursor == ''

    async def test_ip_private(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            add1 = (['inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'],
                    ['bhv.aka.test.mal'])
            add2 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
            add3 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
            add4 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
            remove1 = (['inet:ipv4=11.11.11.11', 'inet:ipv4=6.6.6.6',
                        'inet:ipv4=7.7.7.7'], ['mal'])
            add = (add1, add2, add3, add4)
            remove = (remove1,)
            d_list, c_time = await add_nodes(cortex_db, 'ip', 11, add, remove)
            feed = EvilFeed(logging.getLogger(__name__),
                            'ip', cortex_db=cortex_db)
            result, cursor = await feed.run(limit=1000, is_private=True)
            assert isinstance(result, dict)
            # There are 11 total nodes, we completely remove 11.11.11.11
            assert len(result) == 11
            for node in d_list:
                # if int(node.split('.')[0]) in [11]:
                #     assert node not in result.keys()  # Checking specific nodes are not included
                if int(node.split('.')[0]) in [8, 9, 10]:
                    assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                    assert result[node]['firstSeen'] == c_time
                    if node == '8.8.8.8':
                        assert sorted(['#bhv.test',
                                       '#int.test',
                                       '#int.tlp.ibmonly',
                                       '#mal.wannacry',
                                       '#pwn.test',
                                       '#tgt.test',
                                       '#thr.test',
                                       '#trend.test']) ==\
                                       sorted(result[node]['tags'])
                    elif node == '9.9.9.9':
                        assert sorted(['#bhv.test',
                                       '#int.test',
                                       '#int.tlp.red',
                                       '#mal.wannacry',
                                       '#pwn.test',
                                       '#tgt.test',
                                       '#thr.test',
                                       '#trend.test']) ==\
                                       sorted(result[node]['tags'])
                    elif node == '10.10.10.10':
                        assert sorted(['#bhv.test',
                                       '#int.test',
                                       '#mal.wannacry',
                                       '#omit.legit',
                                       '#pwn.test',
                                       '#tgt.test',
                                       '#thr.test',
                                       '#trend.test']) ==\
                                       sorted(result[node]['tags'])
                elif int(node.split('.')[0]) in [6, 7]:
                    assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                    assert sorted(['#bhv.aka.test.mal',
                                   '#bhv.test',
                                   '#int.test',
                                   '#pwn.test',
                                   '#tgt.test',
                                   '#thr.test',
                                   '#trend.test']) ==\
                                   sorted(result[node]['tags'])
                    assert result[node]['firstSeen'] == c_time
                else:
                    assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
                    # assert sorted(['#bhv.test',
                    #                 '#int.test',
                    #                 '#mal.wannacry',
                    #                 '#pwn.test',
                    #                 '#tgt.test',
                    #                 '#thr.test',
                    #                 '#trend.test']) == sorted(result[node]['tags'])
                    assert '#bhv.test' in sorted(result[node]['tags'])
                    # assert '#mal.wannacry' in sorted(result[node]['tags'])
                    assert '#thr.test' in sorted(result[node]['tags'])
                    assert '#trend.test' in sorted(result[node]['tags'])
                    assert '#int.test' in sorted(result[node]['tags'])
                    assert '#pwn.test' in sorted(result[node]['tags'])
                    assert '#tgt.test' in sorted(result[node]['tags'])
                    assert result[node]['firstSeen'] == c_time
            assert cursor == ''


# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestEvilHashFeed:
#     async def test_hash_public(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#             add1 = (['hash:md5=506be00b6796ea13a38950d3da1b5dee', 'hash:md5=606be00b6796ea13a38950d3da1b5dee'], [
#                     'bhv.aka.test.mal'])
#             add2 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
#                     ['int.tlp.ibmonly'])
#             add3 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
#                     ['int.tlp.red'])
#             add4 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'], ['omit.legit'])
#             remove1 = (['hash:md5=406be00b6796ea13a38950d3da1b5dee', 'hash:md5=506be00b6796ea13a38950d3da1b5dee',
#                         'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['mal'])
#             add = (add1, add2, add3, add4)
#             remove = (remove1,)
#             h_list, c_time = await add_nodes(cortex_db, 'hash', 8, add, remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'hash', cortex_db=cortex_db)
#             result, cursor = await feed.run(limit=1000)
#         assert isinstance(result, dict)
#         # There are 9 total nodes, we remove 426be00b6796ea13a38950d3da1b5dee
#         assert len(result) == 5
#         for node in h_list:
#             if int(node.split('0')[0]) in [4, 7, 8, 9]:
#                 assert node not in result.keys()  # Checking specific nodes are not included
#             elif int(node.split('0')[0]) in [5, 6]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.aka.test.mal', '#bhv.test', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == c_time
#             else:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.test', '#mal.wannacry', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == c_time
#         assert cursor == ''

#     async def test_hash_private(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#             add1 = (['hash:md5=506be00b6796ea13a38950d3da1b5dee',
#                      'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['bhv.aka.test.mal'])
#             add2 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
#                     ['int.tlp.ibmonly'])
#             add3 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
#                     ['int.tlp.red'])
#             add4 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'], ['omit.legit'])
#             remove1 = (['hash:md5=406be00b6796ea13a38950d3da1b5dee', 'hash:md5=506be00b6796ea13a38950d3da1b5dee',
#                         'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['mal'])
#             add = (add1, add2, add3, add4)
#             remove = (remove1,)
#             h_list, c_time = await add_nodes(cortex_db, 'hash', 8, add, remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'hash', cortex_db=cortex_db)
#             result, cursor = await feed.run(limit=1000, is_private=True)
#         assert isinstance(result, dict)
#         # There are 11 total nodes, we remove Com node
#         assert len(result) == 7
#         for node in h_list:
#             if int(node.split('0')[0]) in [4]:
#                 assert node not in result.keys()  # Checking specific nodes are not included
#             elif int(node.split('0')[0]) in [7, 8, 9]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert result[node]['firstSeen'] == c_time
#                 if node == '706be00b6796ea13a38950d3da1b5dee':
#                     assert sorted(['#bhv.test',
#                                '#int.test',
#                                '#int.tlp.ibmonly',
#                                '#mal.wannacry',
#                                '#pwn.test',
#                                '#tgt.test',
#                                '#thr.test',
#                                '#trend.test']) == result[node]['tags']
#                 elif node == '806be00b6796ea13a38950d3da1b5dee':
#                     assert sorted(['#bhv.test',
#                                '#int.test',
#                                '#int.tlp.red',
#                                '#mal.wannacry',
#                                '#pwn.test',
#                                '#tgt.test',
#                                '#thr.test',
#                                '#trend.test']) == result[node]['tags']
#                 elif node == '906be00b6796ea13a38950d3da1b5dee':
#                     assert sorted([]) == result[node]['tags']
#             elif int(node.split('0')[0]) in [5, 6]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.test',
#                                '#int.test',
#                                '#bhv.aka.test.mal',
#                                '#pwn.test',
#                                '#tgt.test',
#                                '#thr.test',
#                                '#trend.test']) == result[node]['tags']
#                 assert result[node]['firstSeen'] == c_time
#             else:
#                 assert {'type', 'seen', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.test',
#                                '#int.test',
#                                '#mal.wannacry',
#                                '#pwn.test',
#                                '#tgt.test',
#                                '#thr.test',
#                                '#trend.test']) ==\
#                                result[node]['tags']
#                 assert result[node]['firstSeen'] == c_time
#         assert cursor == ''


# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestEvilAllFeed:
#     async def test_all_public(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#             # adding domains
#             d_add1 = (['inet:fqdn=6domain.com', 'inet:fqdn=7domain.com'], [
#                 'bhv.aka.test.mal'])
#             d_add2 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly'])
#             d_add3 = (['inet:fqdn=9domain.com'], ['int.tlp.red'])
#             d_add4 = (['inet:fqdn=10domain.com'], ['omit.legit'])
#             d_remove1 = (['inet:fqdn=com', 'inet:fqdn=6domain.com',
#                           'inet:fqdn=7domain.com'], ['mal'])
#             d_add = (d_add1, d_add2, d_add3, d_add4)
#             d_remove = (d_remove1,)
#             d_list, d_time = await add_nodes(cortex_db, 'domain', 8, d_add, d_remove)
#
#             # adding ip
#             i_add1 = (['inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'],
#                       ['bhv.aka.test.mal'])
#             i_add2 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
#             i_add3 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
#             i_add4 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
#             i_remove1 = (['inet:ipv4=11.11.11.11',
#                           'inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'], ['mal'])
#             i_add = (i_add1, i_add2, i_add3, i_add4)
#             i_remove = (i_remove1,)
#             i_list, i_time = await add_nodes(cortex_db, 'ip', 11, i_add, i_remove)
#
#             # adding hash
#             h_add1 = (['hash:md5=506be00b6796ea13a38950d3da1b5dee', 'hash:md5=606be00b6796ea13a38950d3da1b5dee'], [
#                 'bhv.aka.test.mal'])
#             h_add2 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
#                       ['int.tlp.ibmonly'])
#             h_add3 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
#                       ['int.tlp.red'])
#             h_add4 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'],
#                       ['omit.legit'])
#             h_remove1 = (['hash:md5=406be00b6796ea13a38950d3da1b5dee', 'hash:md5=506be00b6796ea13a38950d3da1b5dee',
#                           'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['mal'])
#             h_add = (h_add1, h_add2, h_add3, h_add4)
#             h_remove = (h_remove1,)
#             h_list, h_time = await add_nodes(cortex_db, 'hash', 8, h_add, h_remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'all', cortex_db=cortex_db)
#             result, cursor = await feed.run(limit=1000)
#         assert isinstance(result, dict)
#         assert len(result) == 22
#         # asserts for domains
#         for node in d_list:
#             if int(node.split('d')[0]) in [8, 9, 10]:
#                 assert node not in result.keys()  # Checking specific nodes are not included
#             elif int(node.split('d')[0]) in [6, 7]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.aka.test.mal', '#thr.test', '#bhv.test',
#                         '#trend.test']) == sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == d_time
#             else:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#mal.wannacry', '#thr.test', '#bhv.test',
#                         '#trend.test']) == sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == d_time
#         # asserts for ips
#         for node in i_list:
#             if int(node.split('.')[0]) in [8, 9, 10]:
#                 assert node not in result.keys()  # Checking specific nodes are not included
#             elif int(node.split('.')[0]) in [6, 7]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.aka.test.mal', '#bhv.test', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == i_time
#             else:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 # assert sorted(['#bhv.test', '#mal.wannacry', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
#                 assert '#bhv.test' in sorted(result[node]['tags'])
#                 # assert '#mal.wannacry' in sorted(result[node]['tags'])
#                 assert '#thr.test' in sorted(result[node]['tags'])
#                 assert '#trend.test' in sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == i_time
#         # for node in h_list:
#         #     if int(node.split('0')[0]) in [4, 7, 8, 9]:
#         #         assert node not in result.keys()  # Checking specific nodes are not included
#         #     elif int(node.split('0')[0]) in [5, 6]:
#         #         assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#         #         assert sorted(['#bhv.aka.test.mal', '#bhv.test', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
#         #         assert result[node]['firstSeen'] == h_time
#         #     else:
#         #         assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#         #         assert sorted(['#bhv.test', '#mal.wannacry', '#thr.test', '#trend.test']) == sorted(result[node]['tags'])
#         #         assert result[node]['firstSeen'] == h_time
#         # assert cursor == ''
#
#     async def test_all_private(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#                 # adding domains
#             d_add1 = (['inet:fqdn=6domain.com', 'inet:fqdn=7domain.com'], [
#                       'bhv.aka.test.mal'])
#             d_add2 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly'])
#             d_add3 = (['inet:fqdn=9domain.com'], ['int.tlp.red'])
#             d_add4 = (['inet:fqdn=10domain.com'], ['omit.legit'])
#             d_remove1 = (['inet:fqdn=com', 'inet:fqdn=6domain.com',
#                           'inet:fqdn=7domain.com'], ['mal'])
#             d_add = (d_add1, d_add2, d_add3, d_add4)
#             d_remove = (d_remove1,)
#             d_list, d_time = await add_nodes(cortex_db, 'domain', 8, d_add, d_remove)
#
#             # adding ip
#             i_add1 = (['inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'],
#                       ['bhv.aka.test.mal'])
#             i_add2 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
#             i_add3 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
#             i_add4 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
#             i_remove1 = (['inet:ipv4=11.11.11.11',
#                           'inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'], ['mal'])
#             i_add = (i_add1, i_add2, i_add3, i_add4)
#             i_remove = (i_remove1,)
#             i_list, i_time = await add_nodes(cortex_db, 'ip', 11, i_add, i_remove)
#
#             # adding hash
#             # h_add1 = (['hash:md5=506be00b6796ea13a38950d3da1b5dee', 'hash:md5=606be00b6796ea13a38950d3da1b5dee'], [
#             #     'bhv.aka.test.mal'])
#             # h_add2 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
#             #           ['int.tlp.ibmonly'])
#             # h_add3 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
#             #           ['int.tlp.red'])
#             # h_add4 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'],
#             #           ['omit.legit'])
#             # h_remove1 = (['hash:md5=406be00b6796ea13a38950d3da1b5dee', 'hash:md5=506be00b6796ea13a38950d3da1b5dee',
#             #               'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['mal'])
#             # h_add = (h_add1, h_add2, h_add3, h_add4)
#             # h_remove = (h_remove1,)
#             # h_list, h_time = await add_nodes(cortex_db, 'hash', 8, h_add, h_remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'all', cortex_db=cortex_db)
#             result, cursor = await feed.run(limit=1000, is_private=True)
#         assert isinstance(result, dict)
#         assert len(result) == 20
#         # asserts for domains
#         for node in d_list:
#             if int(node.split('d')[0]) in [8, 9, 10]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert result[node]['firstSeen'] == d_time
#                 if node == '8domain.com':
#                     assert sorted(['#int.tlp.ibmonly', '#thr.test', '#bhv.test',
#                             '#trend.test', '#pwn.test',
#                             '#tgt.test', '#int.test', '#mal.wannacry'])\
#                             == sorted(result[node]['tags'])
#                 elif node == '9domain.com':
#                     assert sorted(['#int.tlp.red', '#thr.test', '#bhv.test',
#                             '#trend.test', '#pwn.test',
#                             '#tgt.test', '#int.test', '#mal.wannacry'])\
#                             == sorted(result[node]['tags'])
#                 elif node == '10domain.com':
#                     assert sorted(['#omit.legit', '#thr.test', '#bhv.test',
#                             '#trend.test', '#pwn.test',
#                             '#tgt.test', '#int.test', '#mal.wannacry'])\
#                             == sorted(result[node]['tags'])
#             elif int(node.split('d')[0]) in [6, 7]:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.aka.test.mal', '#thr.test', '#bhv.test',
#                         '#trend.test', '#pwn.test',
#                         '#tgt.test', '#int.test']) == sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == d_time
#             else:
#                 assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                 assert sorted(['#bhv.test',
#                                '#int.test',
#                                '#mal.wannacry',
#                                '#pwn.test',
#                                '#tgt.test',
#                                '#thr.test',
#                                '#trend.test']) ==\
#                                sorted(result[node]['tags'])
#                 assert result[node]['firstSeen'] == d_time
#
#         # asserts for ips
#         for node in i_list:
#                 # if int(node.split('.')[0]) in [11]:
#                 #     assert node not in result.keys()  # Checking specific nodes are not included
#                 if int(node.split('.')[0]) in [8, 9, 10]:
#                     assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                     assert result[node]['firstSeen'] == i_time
#                     if node == '8.8.8.8':
#                         assert sorted(['#bhv.test',
#                                        '#int.test',
#                                        '#int.tlp.ibmonly',
#                                        '#mal.wannacry',
#                                        '#pwn.test',
#                                        '#tgt.test',
#                                        '#thr.test',
#                                        '#trend.test']) ==\
#                                        sorted(result[node]['tags'])
#                     elif node == '9.9.9.9':
#                         assert sorted(['#bhv.test',
#                                        '#int.test',
#                                        '#int.tlp.red',
#                                        '#mal.wannacry',
#                                        '#pwn.test',
#                                        '#tgt.test',
#                                        '#thr.test',
#                                        '#trend.test']) ==\
#                                        sorted(result[node]['tags'])
#                     elif node == '10.10.10.10':
#                         assert sorted(['#bhv.test',
#                                        '#int.test',
#                                        '#mal.wannacry',
#                                        '#omit.legit',
#                                        '#pwn.test',
#                                        '#tgt.test',
#                                        '#thr.test',
#                                        '#trend.test']) ==\
#                                        sorted(result[node]['tags'])
#                 elif int(node.split('.')[0]) in [6, 7]:
#                     assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                     # assert sorted(['#bhv.aka.test.mal',
#                     #                '#bhv.test',
#                     #                '#int.test',
#                     #                '#pwn.test',
#                     #                '#tgt.test',
#                     #                '#thr.test',
#                     #                '#trend.test']) ==\
#                     #                sorted(result[node]['tags'])
#                     assert '#bhv.test' in sorted(result[node]['tags'])
#                     assert '#int.test' in sorted(result[node]['tags'])
#                     assert '#pwn.test' in sorted(result[node]['tags'])
#                     assert '#tgt.test' in sorted(result[node]['tags'])
#                     assert '#thr.test' in sorted(result[node]['tags'])
#                     assert '#trend.test' in sorted(result[node]['tags'])
#                     assert '#bhv.aka.test.mal' in sorted(result[node]['tags'])
#                     assert result[node]['firstSeen'] == i_time
#                 else:
#                     assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
#                     # assert sorted(['#bhv.test',
#                     #                '#int.test',
#                     #                '#mal.wannacry',
#                     #                '#pwn.test',
#                     #                '#tgt.test',
#                     #                '#thr.test',
#                     #                '#trend.test']) == sorted(result[node]['tags'])
#                     assert '#bhv.test' in sorted(result[node]['tags'])
#                     assert '#int.test' in sorted(result[node]['tags'])
#                     assert '#pwn.test' in sorted(result[node]['tags'])
#                     assert '#tgt.test' in sorted(result[node]['tags'])
#                     assert '#thr.test' in sorted(result[node]['tags'])
#                     assert '#trend.test' in sorted(result[node]['tags'])
#                     # assert '#mal.wannacry' in sorted(result[node]['tags'])
#                     assert result[node]['firstSeen'] == i_time

        # asserts for hash
        # for node in h_list:
        #     if int(node.split('0')[0]) in [4]:
        #         assert node not in result.keys()  # Checking specific nodes are not included
        #     elif int(node.split('0')[0]) in [7, 8, 9]:
        #         assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
        #         assert result[node]['firstSeen'] == h_time
        #         if node == '706be00b6796ea13a38950d3da1b5dee':
        #             assert sorted(['#bhv.test',
        #                        '#int.test',
        #                        '#int.tlp.ibmonly',
        #                        '#mal.wannacry',
        #                        '#pwn.test',
        #                        '#tgt.test',
        #                        '#thr.test',
        #                        '#trend.test']) == result[node]['tags']
        #         elif node == '806be00b6796ea13a38950d3da1b5dee':
        #             assert sorted(['#bhv.test',
        #                        '#int.test',
        #                        '#int.tlp.red',
        #                        '#mal.wannacry',
        #                        '#pwn.test',
        #                        '#tgt.test',
        #                        '#thr.test',
        #                        '#trend.test']) == result[node]['tags']
        #         elif node == '906be00b6796ea13a38950d3da1b5dee':
        #             assert sorted([]) == result[node]['tags']
        #     elif int(node.split('0')[0]) in [5, 6]:
        #         assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
        #         assert sorted(['#bhv.test',
        #                        '#int.test',
        #                        '#bhv.aka.test.mal',
        #                        '#pwn.test',
        #                        '#tgt.test',
        #                        '#thr.test',
        #                        '#trend.test']) == result[node]['tags']
        #         assert result[node]['firstSeen'] == h_time
        #     else:
        #         assert {'type', 'firstSeen', 'lastSeen', 'misc', 'tags'} <= result[node].keys()
        #         assert sorted(['#bhv.test',
        #                        '#int.test',
        #                        '#mal.wannacry',
        #                        '#pwn.test',
        #                        '#tgt.test',
        #                        '#thr.test',
        #                        '#trend.test']) ==\
        #                        result[node]['tags']
        #         assert result[node]['firstSeen'] == h_time
        # assert cursor == ''


# @pytest.mark.usefixtures("setup_config")
# @pytest.mark.asyncio
# class TestEvilCursor:
#     async def test_all_cursor_public(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#                 # adding domains
#             d_add1 = (['inet:fqdn=6domain.com', 'inet:fqdn=7domain.com'], [
#                 'bhv.aka.test.mal'])
#             d_add2 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly'])
#             d_add3 = (['inet:fqdn=9domain.com'], ['int.tlp.red'])
#             d_add4 = (['inet:fqdn=10domain.com'], ['omit.legit'])
#             d_remove1 = (['inet:fqdn=com', 'inet:fqdn=6domain.com',
#                           'inet:fqdn=7domain.com'], ['mal'])
#             d_add = (d_add1, d_add2, d_add3, d_add4)
#             d_remove = (d_remove1,)
#             d_list, d_time = await add_nodes(cortex_db, 'domain', 8, d_add, d_remove)
#
#             # adding ip
#             i_add1 = (['inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'],
#                       ['bhv.aka.test.mal'])
#             i_add2 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
#             i_add3 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
#             i_add4 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
#             i_remove1 = (['inet:ipv4=11.11.11.11',
#                           'inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'], ['mal'])
#             i_add = (i_add1, i_add2, i_add3, i_add4)
#             i_remove = (i_remove1,)
#             i_list, i_time = await add_nodes(cortex_db, 'ip', 11, i_add, i_remove)
#
#             # adding hash
#             # h_add1 = (['hash:md5=506be00b6796ea13a38950d3da1b5dee', 'hash:md5=606be00b6796ea13a38950d3da1b5dee'], [
#             #     'bhv.aka.test.mal'])
#             # h_add2 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
#             #           ['int.tlp.ibmonly'])
#             # h_add3 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
#             #           ['int.tlp.red'])
#             # h_add4 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'],
#             #           ['omit.legit'])
#             # h_remove1 = (['hash:md5=406be00b6796ea13a38950d3da1b5dee', 'hash:md5=506be00b6796ea13a38950d3da1b5dee',
#             #               'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['mal'])
#             # h_add = (h_add1, h_add2, h_add3, h_add4)
#             # h_remove = (h_remove1,)
#             # h_list, h_time = await add_nodes(cortex_db, 'hash', 8, h_add, h_remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'all', cortex_db=cortex_db)
#             set1, cursor = await feed.run(limit=3)
#             vals1 = set1.keys()
#             assert cursor
#             assert int(cursor) > datetime.datetime.timestamp(datetime.datetime.utcnow())
#             assert len(set1) <= 3  # There are 25 total nodes
#             set2, cursor2 = await feed.run(limit=1000, cursor=cursor)
#             vals2 = set2.keys()
#             # # check that same nodes not provided in next set
#             # assert [i for i in vals1 if i in vals2] == ['5domain.com', '106be00b6796ea13a38950d3da1b5dee', '5.5.5.5']
#
#     async def test_domain_cursor_public(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#             # adding domains
#             d_add1 = (['inet:fqdn=6domain.com', 'inet:fqdn=7domain.com'], [
#                 'bhv.aka.test.mal'])
#             d_add2 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly'])
#             d_add3 = (['inet:fqdn=9domain.com'], ['int.tlp.red'])
#             d_add4 = (['inet:fqdn=10domain.com'], ['omit.legit'])
#             d_remove1 = (['inet:fqdn=com', 'inet:fqdn=6domain.com',
#                           'inet:fqdn=7domain.com'], ['mal'])
#             d_add = (d_add1, d_add2, d_add3, d_add4)
#             d_remove = (d_remove1,)
#             d_list, d_time = await add_nodes(cortex_db, 'domain', 8, d_add, d_remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'domain', cortex_db=cortex_db)
#             set1, cursor = await feed.run(limit=3)
#             vals1 = set1.keys()
#             assert int(cursor) > datetime.datetime.timestamp(
#                 datetime.datetime.utcnow())
#             assert len(set1) <= 3  # There are 9 total nodes
#             set2, cursor2 = await feed.run(limit=1000, cursor=cursor)
#             vals2 = set2.keys()
#             # # check that same nodes not provided in next set
#             # assert [i for i in vals1 if i in vals2] == ['3domain.com', '1domain.com', '2domain.com']
#
#     async def test_ip_cursor_public(self):
#         cortex_db = CortexDb(logging.getLogger(__name__), True)
#         async with cortex_db:
#             # adding ip
#             i_add1 = (['inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'],
#                       ['bhv.aka.test.mal'])
#             i_add2 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
#             i_add3 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
#             i_add4 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
#             i_remove1 = (['inet:ipv4=11.11.11.11',
#                           'inet:ipv4=6.6.6.6', 'inet:ipv4=7.7.7.7'], ['mal'])
#             i_add = (i_add1, i_add2, i_add3, i_add4)
#             i_remove = (i_remove1,)
#             i_list, i_time = await add_nodes(cortex_db, 'ip', 11, i_add, i_remove)
#             feed = EvilFeed(logging.getLogger(__name__),
#                             'ip', cortex_db=cortex_db)
#             set1, cursor = await feed.run(limit=5)
#             vals1 = set1.keys()
#             assert int(cursor) > datetime.datetime.timestamp(
#                 datetime.datetime.utcnow())
#             assert len(set1) <= 5  # There are 25 total nodes
#             set2, cursor2 = await feed.run(limit=1000, cursor=cursor)
#             vals2 = set2.keys()
            # # check that same nodes not provided in next set
            # assert [i for i in vals1 if i in vals2] == ['5.5.5.5', '1.1.1.1', '4.4.4.4', '2.2.2.2', '3.3.3.3']

    # async def test_hash_cursor_public(self):
    #     cortex_db = CortexDb(logging.getLogger(__name__), True)
    #     async with cortex_db:
    #         # adding hash
    #         h_add1 = (['hash:md5=506be00b6796ea13a38950d3da1b5dee', 'hash:md5=606be00b6796ea13a38950d3da1b5dee'], [
    #             'bhv.aka.test.mal'])
    #         h_add2 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
    #                   ['int.tlp.ibmonly'])
    #         h_add3 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
    #                   ['int.tlp.red'])
    #         h_add4 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'],
    #                   ['omit.legit'])
    #         h_remove1 = (['hash:md5=406be00b6796ea13a38950d3da1b5dee', 'hash:md5=506be00b6796ea13a38950d3da1b5dee',
    #                       'hash:md5=606be00b6796ea13a38950d3da1b5dee'], ['mal'])
    #         h_add = (h_add1, h_add2, h_add3, h_add4)
    #         h_remove = (h_remove1,)
    #         h_list, h_time = await add_nodes(cortex_db, 'hash', 8, h_add, h_remove)
    #         feed = EvilFeed(logging.getLogger(__name__),
    #                         'hash', cortex_db=cortex_db)
    #         set1, cursor = await feed.run(limit=3)
    #         vals1 = set1.keys()
    #         assert int(cursor) > datetime.datetime.timestamp(
    #             datetime.datetime.utcnow())
    #         assert len(set1) <= 5  # There are 25 total nodes
    #         set2, cursor2 = await feed.run(limit=1000, cursor=cursor)
    #         vals2 = set2.keys()
            # # check that same nodes not provided in next set
            # assert [i for i in vals1 if i in vals2] == ['106be00b6796ea13a38950d3da1b5dee',
            #                                             '306be00b6796ea13a38950d3da1b5dee',
            #                                             '206be00b6796ea13a38950d3da1b5dee']

    async def test_cursor_10_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = EvilFeed(logging.getLogger(__name__),
                            'domain', cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3, cursor=1504882068)
        assert len(set1) <= 2

    async def test_cursor_11_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = EvilFeed(logging.getLogger(__name__),
                            'domain', cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3, cursor=15048820680)
        assert len(set1) <= 2

    async def test_cursor_12_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = EvilFeed(logging.getLogger(__name__),
                            'domain', cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3, cursor=150488206800)
        assert len(set1) <= 2

    async def test_cursor_9_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = EvilFeed(logging.getLogger(__name__),
                            'all', cortex_db=cortex_db)
        with pytest.raises(HttpError):
            await feed.run(limit=3, cursor=4061026)

    async def test_cursor_14_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = EvilFeed(logging.getLogger(__name__),
                            'all', cortex_db=cortex_db)
            with pytest.raises(HttpError):
                await feed.run(limit=3, cursor=33598248468000)


@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestEvilErrors:
    async def test_bad_ioc_type(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        feed = EvilFeed(logging.getLogger(__name__),
                        'badname', cortex_db=cortex_db)
        with pytest.raises(HttpError):
            await feed.run(limit=1000)

    async def test_no_feed_data(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        feed = EvilFeed(logging.getLogger(__name__),
                        'all', cortex_db=cortex_db)
        with pytest.raises(HttpError):
            await feed.run(limit=1000)

    async def test_cursor_no_data(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            feed = EvilFeed(logging.getLogger(__name__),
                            'all', cortex_db=cortex_db)
            with pytest.raises(HttpError):
                await feed.run(limit=3, cursor=1504882068)
