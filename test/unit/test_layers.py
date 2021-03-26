import pytest
import logging
import synapse.tests.utils as s_t_utils
from libs.config import set_root_dir, set_profile, find_config_dir
from libs.cortex_db import CortexDb, read_async
from libs.synapse_models.cortex_users import CortexUser
from libs.synapse_models.layers import SynLayers


@pytest.fixture(scope='session')
def setup_config():
    set_root_dir(find_config_dir())
    set_profile('test')
    return True

async def get_main_layer(syndb):
    query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
    result = await read_async(None, syndb.conn(), query)
    msg = eval(result[0][1]['mesg'])
    return msg['iden']

@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_config")
class TestStormLayers(s_t_utils.SynTest):
    async def test_view_layer_list(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            result = await read_async(None, cortex_db.conn(), query)
            msg = eval(result[0][1]['mesg'])
            assert 'iden' in msg
            assert 'name' in msg
            vlist = {'iden': msg['iden'], 'name': msg['name']}
            assert 'iden' in vlist
            assert 'name' in vlist

    async def test_create_forked_view(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            #adding users
            await CortexUser(logger, cortex_db).add_users()
            #Switching user
            new_conn = await cortex_db.switch_conn(user='layr')
            # Create forked view
            vlist = []
            main_iden = await get_main_layer(cortex_db)
            fork_query = f'view.fork {main_iden} --name test'
            await read_async(None, new_conn, fork_query)
            # Get all views
            query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            result = await read_async(None, cortex_db.conn(), query)
            for view in result:
                msg = eval(view[1]['mesg'])
                vlist.append({'iden': msg['iden'], 'name': msg['name']})
            for item in vlist:
                assert 'iden' in item
                assert item['name'] in ['default', 'test']

    async def test_create_new_view_layer(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            #adding users
            await CortexUser(logger, cortex_db).add_users()
            #Switching user
            new_conn = await cortex_db.switch_conn(user='layr')
            # Create forked view
            vlist = []
            layer_query = f'$layr=$lib.layer.add() $iden=$lib.view.add(layers=($layr.iden,)).iden view.set $iden name test'
            await read_async(None, new_conn, layer_query)
            query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            result = await read_async(None, cortex_db.conn(), query)
            for view in result:
                msg = eval(view[1]['mesg'])
                vlist.append({'iden': msg['iden'], 'name': msg['name']})
            for item in vlist:
                assert 'iden' in item
                assert item['name'] in ['default', 'test']

    async def test_delete_view_layer(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            # User Queries
            await CortexUser(logger, cortex_db).add_users()
            new_conn = await cortex_db.switch_conn(user='layr')  # Switching Connection
            layr_user = await new_conn.getUserInfo('layr')  # Get User Info
            layr_user_iden = layr_user.get('iden')  # Get Layer User Uniq Iden

            # View & Layer Queries
            vlist = []
            query_cr_lyer_and_view = f'$layr=$lib.layer.add() $iden=$lib.view.add(layers=($layr.iden,)).iden view.set $iden name test'
            await read_async(None, new_conn, query_cr_lyer_and_view)
            all_views_query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            result = await read_async(None, cortex_db.conn(), all_views_query)

            # Place views in list
            for view in result:
                msg = eval(view[1]['mesg'])
                vlist.append({'iden': msg['iden'], 'name': msg['name'], 'creator': msg['creator']})
            # Iterate view list and get view iden and layer iden to delete
            for item in vlist:
                if item['creator'] == layr_user_iden:
                    v_iden = item['iden']
                    v_query = f'$lib.print($lib.view.get({v_iden}).pack())'
                    v_result = await read_async(None, new_conn, v_query)
                    # This is the query we plan to use to get one view in production.
                    # Testing wise there's no need for this redudant check
                    for v_item in v_result:
                        v_msg = eval(v_item[1]['mesg'])
                        single_view_iden = v_msg['iden']
                        single_view_layers = v_msg['layers']
                    single_view_query = f'$lib.view.del({single_view_iden})'
                    await read_async(None, new_conn, single_view_query) # Removing View first
                    for s_layer in single_view_layers:
                        if s_layer['creator'] == layr_user_iden:
                            l_iden = s_layer['iden']
                            l_query = f'$lib.layer.del({l_iden})'
                            await read_async(None, new_conn, l_query) # Removing layer
            get_all_views_updated_query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            new_view_list = await read_async(None, new_conn, get_all_views_updated_query)
            assert new_view_list

@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_config")
class TestSynLayers(s_t_utils.SynTest):
    async def test_view_layers(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            syn_layer = SynLayers(logger, cortex_db)
            result = await syn_layer.get_all_views()
            for view in result:
                assert 'iden' in view
                assert 'name' in view

    async def test_create_forked_view(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            #adding users
            await CortexUser(logger, cortex_db).add_users()
            syn_layer = SynLayers(logger, cortex_db)
            result = await syn_layer.create_views('test', fork=True, user='layr')
            for view in result:
                assert 'iden' in view
                assert view['name'] in ['test']

    async def test_create_new_view_layer(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            #adding users
            await CortexUser(logger, cortex_db).add_users()
            syn_layer = SynLayers(logger, cortex_db)
            result = await syn_layer.create_views('test', user='layr')
            for view in result:
                assert 'iden' in view
                assert view['name'] in ['test']

    async def test_delete_view_layer(self):
        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            #adding users
            await CortexUser(logger, cortex_db).add_users()
            syn_layer = SynLayers(logger, cortex_db)
            result = await syn_layer.create_views('test', user='layr')
            iden = result[0]['iden']
            result = await syn_layer.delete_view(iden, user='layr')
            assert result == []

    async def test_quick_layers(self):

        async def create_layer_view(new_conn, viewname):
            iden = None
            viewiden = None
            layer_query = f'$layr=$lib.layer.add() $iden=$lib.view.add(layers=($layr.iden,)).iden view.set $iden name {viewname}'
            await read_async(None, new_conn, layer_query)
            query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            result = await read_async(None, cortex_db.conn(), query)
            for view in result:
                viewrslt= eval(view[1]['mesg'])
                if viewrslt['name'] == viewname:
                   viewiden = viewrslt['iden']
                   iden = viewrslt['layers'][0]['iden']
            await read_async(None, cortex_db.conn(), f"[inet:fqdn={viewname}.com]", view=viewiden)
            return iden


        logger = logging.getLogger(__name__)
        cortex_db = CortexDb(logger, True)
        async with cortex_db:
            # #adding users
            # await CortexUser(logger, cortex_db).add_users()
            # #Switching user
            # new_conn = await cortex_db.switch_conn(user='layr')
            # Create forked view
            vlist = []
            #Creating each view and layer and adding nodes
            vtiden = await create_layer_view(cortex_db.conn(), 'virustotal')
            maxmindiden = await create_layer_view(cortex_db.conn(), 'maxmind')
            ipvoididen = await create_layer_view(cortex_db.conn(), 'ipvoid')

            layer_query = f'''$iden=$lib.view.add(layers=({vtiden}, {maxmindiden}, {ipvoididen})).iden 
                              view.set $iden name quickviews | inet:fqdn | $lib.view.del() '''
            await read_async(None, cortex_db.conn(), layer_query)
            query = "for $view in $lib.view.list() { $lib.print($view.pack()) }"
            result = await read_async(None, cortex_db.conn(), query)
            for view in result:
                viewrslt= eval(view[1]['mesg'])
                if viewrslt['name'] == 'quickviews':
                    viewiden = viewrslt['iden']
            quickresult = await read_async(None, cortex_db.conn(), f"inet:fqdn", view=viewiden)
            await read_async(None, cortex_db.conn(), f"$lib.view.del({viewiden})", view=viewiden)
            assert quickresult



#
#     async def test_trigger(self):
#         with self.getTestDir() as dirn:
#
#             async with self.getTestCore(dirn=dirn) as core:
#
#                 # brian = await core.auth.addUser('brian')
#                 # await brian.setPasswd('secret')
#                 #
#                 # await core.auth.rootuser.setPasswd('secret')
#                 # host, port = await core.dmon.listen('tcp://127.0.0.1:0/')
#
#                 # setup a trigger so we know when the nodes move...
#                 result = await core.callStorm('trigger.add node:add --form inet:ipv4 --query {[ +#mytag ]}')
#                 result2 = await core.callStorm('trigger.list')
#                 assert result2 == ''
#
# @pytest.mark.asyncio
# @pytest.mark.usefixtures("setup_config")
# class TestTrigger():
#     async def test_trigger(self):
#         def trigger_model(type='node:add', form=None, tag=None, query=''):
#             trigger_model = {
#                 'trigger': 'add',
#                 'type': type,
#                 'form': form,
#                 'tag': tag,
#                 'query': query
#             }
#             return trigger_model
#
        # # check the tag property successfully added
        # logger = logging.getLogger(__name__)
        # cortex_db = CortexDb(logger, True)
        # test1 = trigger_model(type='tag:add', form='inet:url', tag='omit.tranco', query='{ $omit=$tag { -> inet:fqdn [ +#$omit ]} }')
        # trigger_list = [test1]
        # async with cortex_db:
        #     for trigger in trigger_list:
        #         trigger_query = 'trigger.%s %s ' % (trigger['trigger'], trigger['type'])
        #         trigger_query += '--form %s ' % (trigger['form']) if trigger['form'] else ''
        #         trigger_query += '--tag %s ' % (trigger['tag']) if trigger['tag'] else ''
        #         trigger_query += '--query %s ' % (trigger['query'])
        #         await read_async(None, cortex_db.conn(), trigger_query)
#             url = 'https://www.google.com/test'
#             domain = urlparse(url).netloc
#             await read_async(None, cortex_db.conn(), '[ inet:url=https://www.google.com/test ]')
#             await read_async(None, cortex_db.conn(), f' inet:fqdn={domain} [ +#omit.tranco ]')
#             ioc_result = await read_async(None, cortex_db.conn(), 'inet:url inet:fqdn')
#             result = await read_async(None, cortex_db.conn(), 'trigger.list')
#         assert ioc_result == ''
#         for item in result:
#             if not ('en?' and 'storm query') in item[1]['mesg']:
#                 if test1['query'] in item[1]['mesg']:
#                      assert test1['type'] in item[1]['mesg']
#
