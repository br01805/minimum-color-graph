import logging
import pytest
import time
import datetime
import helpers.http_errors as errors
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async
from libs.synapse_models.bulk_feed import BulkFeed
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
    d_tags = ['mal.test', 'pwn.test',
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

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestBulkFeed:
    async def test_all_public(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            # adding domains
            d_add1 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly'])
            d_add2 = (['inet:fqdn=9domain.com'], ['int.tlp.red'])
            d_add3 = (['inet:fqdn=10domain.com'], ['omit.legit'])
            d_add = (d_add1, d_add2, d_add3)
            d_list, d_time = await add_nodes(cortex_db, 'domain', 8, d_add)

            # adding ip
            i_add1 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
            i_add2 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
            i_add3 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
            i_add = (i_add1, i_add2, i_add3)
            i_list, i_time = await add_nodes(cortex_db, 'ip', 11, i_add)

            # adding hash
            h_add1 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
                      ['int.tlp.ibmonly'])
            h_add2 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
                      ['int.tlp.red'])
            h_add3 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'],
                      ['omit.legit'])
            h_add = (h_add1, h_add2, h_add3)
            h_list, h_time = await add_nodes(cortex_db, 'hash', 8, h_add)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            result, cursor = await feed.run(limit=1000)
        assert isinstance(result, dict)
        assert len(result) == 22
        # asserts for domains
        for node in d_list:
            if int(node.split('d')[0]) in [8, 9, 10]:
                assert node not in result.keys()  # Checking specific nodes are not included
            else:
                assert {'type', 'seen', 'tags'} <= result[node].keys()
                assert sorted(['#mal.test', '#tgt.test',
                               '#int.test', '#thr.test',
                               '#bhv.test', '#trend.test']) ==\
                               sorted(result[node]['tags'])
                assert result[node]['seen'] == d_time
        # asserts for ips
        for node in i_list:
            if int(node.split('.')[0]) in [8, 9, 10]:
                assert node not in result.keys()  # Checking specific nodes are not included
            else:
                assert {'type', 'seen', 'tags'} <= result[node].keys()
                assert sorted(['#mal.test', '#tgt.test',
                               '#int.test', '#thr.test',
                               '#bhv.test', '#trend.test']) ==\
                               sorted(result[node]['tags'])
                assert result[node]['seen'] == i_time
        for node in h_list:
            if int(node.split('0')[0]) in [7, 8, 9]:
                assert node not in result.keys()  # Checking specific nodes are not included
            else:
                assert {'type', 'seen', 'tags'} <= result[node].keys()
                assert sorted(['#mal.test', '#tgt.test',
                               '#int.test', '#thr.test',
                               '#bhv.test', '#trend.test']) ==\
                               sorted(result[node]['tags'])
                assert result[node]['seen'] == h_time
        assert cursor == ''

@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestBulkFeedCursor:
    async def test_all_cursor_public(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            # adding domains
            d_add1 = (['inet:fqdn=8domain.com'], ['int.tlp.ibmonly'])
            d_add2 = (['inet:fqdn=9domain.com'], ['int.tlp.red'])
            d_add3 = (['inet:fqdn=10domain.com'], ['omit.legit'])
            d_add = (d_add1, d_add2, d_add3)
            d_list, d_time = await add_nodes(cortex_db, 'domain', 8, d_add)

            # adding ip
            i_add1 = (['inet:ipv4=8.8.8.8'], ['int.tlp.ibmonly'])
            i_add2 = (['inet:ipv4=9.9.9.9'], ['int.tlp.red'])
            i_add3 = (['inet:ipv4=10.10.10.10'], ['omit.legit'])
            i_add = (i_add1, i_add2, i_add3)
            i_list, i_time = await add_nodes(cortex_db, 'ip', 11, i_add)

            # adding hash
            h_add1 = (['hash:md5=706be00b6796ea13a38950d3da1b5dee'],
                      ['int.tlp.ibmonly'])
            h_add2 = (['hash:md5=806be00b6796ea13a38950d3da1b5dee'],
                      ['int.tlp.red'])
            h_add3 = (['hash:md5=906be00b6796ea13a38950d3da1b5dee'],
                      ['omit.legit'])
            h_add = (h_add1, h_add2, h_add3)
            h_list, h_time = await add_nodes(cortex_db, 'hash', 8, h_add)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3)
            vals1 = set1.keys()
            assert cursor
            assert int(cursor) > datetime.datetime.timestamp(datetime.datetime.utcnow())
            assert len(set1) <= 3  # There are 25 total nodes
            set2, cursor2 = await feed.run(limit=1000, cursor=cursor)
            vals2 = set2.keys()

    async def test_cursor_10_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3, cursor=1504882068)
        assert len(set1) <= 2

    async def test_cursor_11_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3, cursor=15048820680)
        assert len(set1) <= 2

    async def test_cursor_12_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            set1, cursor = await feed.run(limit=3, cursor=150488206800)
        assert len(set1) <= 2

    async def test_cursor_9_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
        with pytest.raises(HttpError):
            await feed.run(limit=3, cursor=4061026)

    async def test_cursor_14_digits(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            await add_nodes(cortex_db, 'domain', 1)
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            with pytest.raises(HttpError):
                await feed.run(limit=3, cursor=33598248468000)


@pytest.mark.usefixtures("setup_config")
@pytest.mark.asyncio
class TestBulkFeedErrors:
    async def test_no_feed_data(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        feed = BulkFeed(logging.getLogger(__name__),
                        cortex_db=cortex_db)
        with pytest.raises(ResourceMissingError):
            await feed.run(limit=1000)

    async def test_cursor_no_data(self):
        cortex_db = CortexDb(logging.getLogger(__name__), True)
        async with cortex_db:
            feed = BulkFeed(logging.getLogger(__name__),
                            cortex_db=cortex_db)
            with pytest.raises(ResourceMissingError):
                await feed.run(limit=3, cursor=1504882068)
