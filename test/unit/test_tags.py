import pytest
import logging
from helpers.http_errors import ResourceMissingError, ConstraintError, ResourceExistsError, ParameterError
from helpers.tag_utils import analyze_name
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async, set_tag_props
from libs.synapse_models.tags import Tags, TagCreate, TagGet, TagGetVerify, TagsSearch, TagDelete, TagUpdate, WhooshSearch

db_tags = [
    {
        'name': 'int.tag1',
        'title': 'The fox and the red fence',
        'doc': 'The quick brown fox jumped over the red fence',
        'created': '2019/01/01T00:00Z',
    },
    {
        'name': 'thr.tag1',
        'title': 'The wolf and the orange fence',
        'doc': 'The quick gray wolf jumped over the orange fence',
        'created': '2019/01/01T00:00Z',
    },
    {
        'name': 'tgt.level1.level2.tag1',
        'title': 'The beetle and the blue fence',
        'doc': 'The quick black beetle cawled over the blue fence',
        'created': '2019/01/01T00:00Z',
    },
    {
        'name': 'tgt.level1.level2',
        'title': 'Level two tag',
        'doc': 'Level two is harder to win.',
        'created': '2019/01/01T00:00Z',
    },
    {
        'name': 'int.SNAKE.black',
        'title': 'The snake and the silver fence',
        'doc': 'The quick black snake slithered over the silver fence',
        'created': '2019/01/01T00:00Z',
    },
    {
        'name': 'int.rabbit.fluffy',
        'title': 'Rabbit Run',
        'doc': 'The rabbit can run',
        'created': '2019/01/01T00:00Z',
    },
    {
        'name': 'int.squirrel.fluffy',
        'title': 'The "grey" squirrel.',
        'doc': 'Quick(grey)squirrel\'jumped\'"red"fence.',
        'created': '2019/01/01T00:00Z',
    },
]


def get_map(tag_list):
    new_list = {}
    for tag in tag_list:
        tag_copy = tag.copy()
        del tag_copy['name']
        new_list[tag['name']] = tag_copy
    return new_list

@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

@pytest.mark.usefixtures("setup_config")
class TestTags():

    @staticmethod
    def count_tags(tags):
        all_tags = set()
        for tag in tags:
            labels = tag['name'].split('.')
            label_name = ''
            for label in labels:
                label_name += label
                all_tags.add(label_name)
                label_name += '.'
        return len(all_tags)

    def test_is_root_tag(self):
        logger = logging.getLogger(__name__)
        tags = Tags(logger)
        assert tags.is_root('int.')
        assert tags.is_root('int')
        assert tags.is_root('int ')
        assert tags.is_root('#int.')
        assert tags.is_root(' #int. ')
        assert tags.is_root(' #INT. ')
        assert not tags.is_root('.int ')
        assert not tags.is_root('foo. ')
        assert not tags.is_root('')
        assert not tags.is_root('.')

    def test_is_valid(self):
        logger = logging.getLogger(__name__)
        tags = Tags(logger)
        assert tags.is_valid('int.abc')[0]
        assert tags.is_valid('int.9abc')[0]
        assert tags.is_valid('int.a_b')[0]
        assert tags.is_valid('int.a-b')[0]
        assert tags.is_valid('INT.ABC')[0]
        assert tags.is_valid('int.ABC')[0]
        assert not tags.is_valid('int.')[0]
        assert not tags.is_valid('foo.')[0]

    def test_validate_req_params(self):
        logger = logging.getLogger(__name__)
        tags = Tags(logger)
        test_tag = {
            'name': '',
            'title': 'Level two tag',
            'doc': 'Level two is harder to win.'
        }
        with pytest.raises(ParameterError):
            tags.validate_req_param('', test_tag, 'create')

    def test_analyze_tag(self):
        logger = logging.getLogger(__name__)
        tags = analyze_name('int')
        assert tags['status'] == 'success'
        assert tags['tree'][0] == 'int'

        tags = analyze_name('int.abc')
        assert tags['status'] == 'success'
        assert tags['tree'][0] == 'int'
        assert tags['tree'][1] == 'int.abc'

        tags = analyze_name('INT.ABC')
        assert tags['status'] == 'success'
        assert tags['tree'][0] == 'int'
        assert tags['tree'][1] == 'int.abc'

        tags = analyze_name('int.abc.')
        assert tags['status'] == 'success'
        assert tags['tree'][0] == 'int'
        assert tags['tree'][1] == 'int.abc'

        tags = analyze_name('int.aB-c_d')
        assert tags['status'] == 'success'
        assert tags['tree'][0] == 'int'
        assert tags['tree'][1] == 'int.ab-c_d'

        tags = analyze_name('foo.abc')
        assert tags['status'] == 'failure'
        assert 'tree' not in tags

        tags = analyze_name(' int.abc.wxy% ')
        assert tags['status'] == 'failure'
        assert 'tree' not in tags

        tags = analyze_name(' int..abc ')
        assert tags['status'] == 'failure'
        assert tags['validLabels'] == False
        assert 'tree' not in tags

        with pytest.raises(ValueError):
            tags = analyze_name('')

    @pytest.mark.asyncio
    async def test_search_tags(self):
        logger = logging.getLogger(__name__)
        tags = TagsSearch(logger, None, add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], list)
        assert len(result['data']) == TestTags.count_tags(db_tags)
        assert 'name' in result['data'][0]
        assert 'title' in result['data'][0]
        assert 'doc' in result['data'][0]

    @pytest.mark.asyncio
    async def test_search_docs_root_tag(self):
        logger = logging.getLogger(__name__)
        tags = TagsSearch(logger, 'int.', add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], list)
        assert len(result['data']) == 8

    @pytest.mark.asyncio
    async def test_search_docs_root_tag_with_hash(self):
        logger = logging.getLogger(__name__)
        tags = TagsSearch(logger, '#int.', add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], list)
        assert len(result['data']) == 8

    @pytest.mark.asyncio
    async def test_search_docs_keyword(self):
        logger = logging.getLogger(__name__)
        tags = TagsSearch(logger, 'brown fox', add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], list)
        assert len(result['data']) == 1

    @pytest.mark.asyncio
    async def test_get_tag(self):
        logger = logging.getLogger(__name__)
        tags = TagGet(logger, db_tags[0]['name'], add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], dict)
        assert 'name' in result['data']
        assert 'title' in result['data']
        assert 'doc' in result['data']
        assert result['data']['name'] == db_tags[0]['name']
        assert result['data']['title'] == db_tags[0]['title']
        assert result['data']['doc'] == db_tags[0]['doc']

    @pytest.mark.asyncio
    async def test_create_tag(self):
        logger = logging.getLogger(__name__)
        tags = TagCreate(logger, db_tags[0])
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert result['data']['name'] == db_tags[0]['name']
        assert result['data']['title'] == db_tags[0]['title']
        assert result['data']['doc'] == db_tags[0]['doc']

    @pytest.mark.asyncio
    async def test_create_tag_no_doc(self):
        logger = logging.getLogger(__name__)
        the_tag = db_tags[0].copy()
        del the_tag['doc']
        tags = TagCreate(logger, the_tag)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert result['data']['name'] == db_tags[0]['name']
        assert result['data']['title'] == db_tags[0]['title']
        assert not result['data']['doc']

    @pytest.mark.asyncio
    async def test_create_tag_escaped_characters(self):
        logger = logging.getLogger(__name__)
        tags = TagCreate(logger, db_tags[-1])
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert result['data']['name'] == db_tags[-1]['name']
        assert result['data']['title'] == db_tags[-1]['title']
        assert result['data']['doc'] == db_tags[-1]['doc']

    @pytest.mark.asyncio
    async def test_create_tag_duplicate(self):
        logger = logging.getLogger(__name__)
        with pytest.raises(ResourceExistsError):
            tags = TagCreate(logger, db_tags[0], None, None, [db_tags[0]])
            await tags.run()

    @pytest.mark.asyncio
    async def test_update_tag(self):
        logger = logging.getLogger(__name__)
        tag_name = 'int.tag1'
        db_update = {
            'title': 'The rhino and the purple fence',
            'doc': 'The quick gray rhino jumped over the purple fence',
        }

        tags = TagUpdate(logger, tag_name, db_update, None, None, add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert 'data' in result
        assert result['data']['name'] == tag_name
        assert result['data']['doc'] == db_update['doc']
        assert result['data']['title'] == db_update['title']

    @pytest.mark.asyncio
    async def test_update_tag_single_field(self):
        logger = logging.getLogger(__name__)
        tag_name = 'int.tag1'
        db_update = {
            'title': 'The rhino and the purple fence',
        }

        tags = TagUpdate(logger, tag_name, db_update, None, None, add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert 'data' in result
        assert result['data']['name'] == tag_name
        assert result['data']['title'] == db_update['title']
        assert result['data']['doc'] == db_tags[0]['doc']

    @pytest.mark.asyncio
    async def test_update_tag_missing(self):
        logger = logging.getLogger(__name__)
        tag_name = 'int.tag1'
        db_update = {
            'title': 'The rhino and the purple fence',
            'doc': 'The quick gray rhino jumped over the purple fence',
        }

        with pytest.raises(ResourceMissingError):
            tags = TagUpdate(logger, tag_name, db_update)
            await tags.run()

    @pytest.mark.asyncio
    async def test_delete_tag(self):
        logger = logging.getLogger(__name__)
        tag_name = db_tags[2]['name']
        db_nodes = (
            ('10.10.10.10', ['int.tag1', 'int.tag2']),
            ('10.10.10.11', ['int.tag2']),
            ('10.10.10.12', [db_tags[2]['name']]),
        )

        tags = TagDelete(logger, tag_name, None, None, add_tags=db_tags, add_nodes=db_nodes)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert 'data' in result

    @pytest.mark.asyncio
    async def test_delete_tag_multiple_nodes(self):
        logger = logging.getLogger(__name__)
        tag_name = db_tags[2]['name']
        db_nodes = (
            ('10.10.10.10', ['int.tag1', 'int.tag2']),
            ('10.10.10.11', ['int.tag1']),
        )

        tags = TagDelete(logger, 'int.tag1', None, None, add_tags=db_tags, add_nodes=db_nodes)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert 'data' in result
        assert {'name', 'title', 'doc', 'created'} <= result['data'].keys()

    @pytest.mark.asyncio
    async def test_delete_tag_missing(self):
        logger = logging.getLogger(__name__)
        tag_name = 'tgt.level1.level3'
        db_nodes = (
            ('10.10.10.12', [db_tags[2]['name']]),
        )

        with pytest.raises(ResourceMissingError):
            tags = TagDelete(logger, tag_name, None, None, add_tags=db_tags, add_nodes=db_nodes)
            result = await tags.run()

    @pytest.mark.asyncio
    async def test_delete_tag_has_children(self):
        logger = logging.getLogger(__name__)
        tag_name = 'tgt.level1'
        db_nodes = (
            ('10.10.10.12', [db_tags[2]['name']]),
        )

        with pytest.raises(ConstraintError):
            tags = TagDelete(logger, tag_name, None, None, add_tags=db_tags, add_nodes=db_nodes)
            result = await tags.run()

    @pytest.mark.asyncio
    async def test_get_verify(self):
        logger = logging.getLogger(__name__)
        tags = TagGetVerify(logger, db_tags[2]['name'], add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], dict)
        assert 'name' in result['data']
        assert 'validChars' in result['data']
        assert 'validLabels' in result['data']
        assert 'hasChildren' in result['data']
        assert 'hasParents' in result['data']
        assert 'isRoot' in result['data']
        assert 'tree' in result['data']
        assert 'exists' in result['data']
        assert result['data']['name'] == db_tags[2]['name']
        assert result['data']['validChars']
        assert result['data']['validLabels']
        assert result['data']['hasParents']
        assert not result['data']['hasChildren']
        assert result['data']['isRoot']
        assert result['data']['exists']

    @pytest.mark.asyncio
    async def test_get_verify_children(self):
        logger = logging.getLogger(__name__)
        tags = TagGetVerify(logger, db_tags[3]['name'], add_tags=db_tags)
        result = await tags.run()
        assert result['msg'] == 'success'
        assert result['status'] == 0
        assert isinstance(result['data'], dict)
        assert 'name' in result['data']
        assert 'hasChildren' in result['data']
        assert result['data']['hasChildren']


def indexMatching(seq, condition):
    for i, x in enumerate(seq):
        if condition(x):
            return i
    return -1

@pytest.mark.usefixtures("setup_config")
class TestWhoosh:
    def test_connecting_word_search_fox(self):
        logger = logging.getLogger(__name__)
        whoosh = WhooshSearch(logger, get_map(db_tags), True)
        result = whoosh.search('brown fox')
        assert len(result) >= 1
        find_tag = list(filter(lambda doc_name: doc_name == 'int.tag1', result))
        assert find_tag

    def test_connecting_word_search_fence(self):
        logger = logging.getLogger(__name__)
        whoosh = WhooshSearch(logger, get_map(db_tags), True)
        result = whoosh.search('jumped fence')
        assert len(result) == 3
        find_tag = list(filter(lambda doc_name: doc_name == 'int.tag1', result))
        assert find_tag

    def test_label_search(self):
        logger = logging.getLogger(__name__)
        whoosh = WhooshSearch(logger, get_map(db_tags), True)
        result = whoosh.search('tag1')
        assert len(result) == 3
        find_tag = list(filter(lambda doc_name: doc_name in ('int.tag1', 'thr.tag1'), result))
        assert find_tag
        assert len(find_tag) == 2

    def test_connecting_word_search_keyword(self):
        logger = logging.getLogger(__name__)
        whoosh = WhooshSearch(logger, get_map(db_tags), True)
        result = whoosh.search('fluffy')
        assert len(result) == 2
        find_tag = list(filter(lambda doc_name: doc_name == 'int.rabbit.fluffy', result))
        assert find_tag

    def test_add_doc(self):
        the_map = get_map(db_tags)
        logger = logging.getLogger(__name__)
        whoosh = WhooshSearch(logger, the_map, True)
        whoosh.add('int.bird.gold', 'The bird and the tall fence', 'The quick bird flew over the tall fence', '2019-01-01T00:00Z')
        result = whoosh.search('flew fence')
        assert len(result) == 1
        find_tag = list(filter(lambda doc_name: doc_name == 'int.bird.gold', result))
        assert find_tag

        result = whoosh.search('gold')
        assert len(result) == 1
        find_tag = list(filter(lambda doc_name: doc_name == 'int.bird.gold', result))
        assert find_tag

    def test_delete_doc(self):
        the_map = get_map(db_tags)
        logger = logging.getLogger(__name__)
        whoosh = WhooshSearch(logger, the_map, True)
        whoosh.remove('int.tag1')
        result = whoosh.search('jumped fence')
        assert len(result) == 2
        find_tag = list(filter(lambda doc_name: doc_name == 'thr.tag1', result))
        assert find_tag

# @pytest.mark.asyncio
# @pytest.mark.usefixtures("setup_config")
# class TestTagProps():
#     async def test_add_tagprop(self):
#         # For each tag_prop: Import from config folder
#         # add to Synapse
#         # check the tag property successfully added
#         logger = logging.getLogger(__name__)
#         cortex_db = CortexDb(logger, True)
#         interval = ('interval', ('str', {}), {'doc': 'interval in seconds'})
#         vendor = ('detection', ('str', {}), {'doc': 'vendor scan result'})
#         props = (interval, vendor)
#         async with cortex_db:
#             await set_tag_props(logger, cortex_db, props)
#             result = await read_async(None, cortex_db.conn(), 'syn:tagprop')
#         prop_list = [prop[1][0][1] for prop in result]
#         assert 'interval' in prop_list
#         assert 'detection' in prop_list

