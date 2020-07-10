import asyncio
import time
import os
import logging
from ndnpnp.controller import Controller
from ndnpnp.db_storage import *
from ndn.encoding import Name
from PIL import Image
from pyzbar.pyzbar import decode
import json
from aiohttp import web
import socketio
import aiohttp_jinja2
import jinja2
from datetime import datetime

int_to_service_mapping = {

}

def app_main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}', datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG, style='{')

    base_path = os.getcwd()
    # Serve static content from /static
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(os.path.join(base_path, 'templates')))
    app.router.add_static(prefix='/static', path=os.path.join(base_path, 'static'))
    routes = web.RouteTableDef()
    # Create SocketIO async server for controller
    sio = socketio.AsyncServer(async_mode='aiohttp')
    sio.attach(app)
    controller = Controller(sio.emit)
    controller.system_init()

    def render_template(template_name, request, **kwargs):
        return aiohttp_jinja2.render_template(template_name, request, context=kwargs)

    def redirect(route_name, request, **kwargs):
        raise web.HTTPFound(request.app.router[route_name].url_for().with_query(kwargs))

    def process_list(lst):
        for it in lst:
            for k, v in it.items():
                if isinstance(v, bytes):
                    it[k] = v.decode()

    @routes.get('/')
    @aiohttp_jinja2.template('index.html')
    async def index(request):
        return

    @routes.get('/system-overview')
    @aiohttp_jinja2.template('system-overview.html')
    async def system_overview(request):
        metainfo = []
        metainfo.append({"information":"System Prefix", "value": controller.system_prefix})
        metainfo.append({"information": "Available Devices", "value": str(len(controller.device_list.devices))})
        return {'metainfo': metainfo}

    # device list
    @routes.get('/device-list')
    @aiohttp_jinja2.template('device-list.html')
    async def device_list(request):
        ret = []
        for device in controller.device_list.devices:
            if device.device_ip == None or device.device_port == None:
                ret.append({'device_name': Name.to_str(device.device_name),
                            'device_ip': 'empty',
                            'device_port': 'empty',
                            'device_activeness': bytes(device.device_active).decode()})
            else:              
                ret.append({'device_name': Name.to_str(device.device_name),
                            'device_ip': bytes(device.device_ip).decode(),
                            'device_port': bytes(device.device_port).decode(),
                            'device_activeness': bytes(device.device_active).decode()})
        return {'device_list': ret}

    @routes.post('/delete/device')
    async def remove_device(request):
        data = await request.json()
        # delete from keychain
        try:
            # TODO bring this line back when the identity delete bug is fixed
            # controller.app.keychain.del_identity(data['deviceIdentityName'])
            os.system('ndnsec-delete ' + data['device_name'])
        except KeyError:
            pass  # great, the key has already been removed
        # delete from database
        controller.device_list.devices = [device for device in controller.device_list.devices
                                          if Name.to_str(device.device_name) != data['device_name']]
        return web.json_response({"st_code": 200})

    @routes.get('/send-interest')
    @aiohttp_jinja2.template('send-interest.html')
    async def send_interest(request):
        return

    @routes.post('/exec/send-interest')
    async def exec_send_interest(request):
        r_json = await request.json()
        name = r_json['name']
        can_be_prefix = r_json['can_be_prefix']
        must_be_fresh = r_json['must_be_fresh']
        signed_interest = r_json['signed_interest']
        param = r_json['application_parameter']

        st_time = time.time()
        ret = await controller.express_interest(name, param.encode(), must_be_fresh, can_be_prefix, signed_interest)
        ed_time = time.time()

        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return web.json_response(ret)

    @routes.get('/manage-policy', name='manage-policy')
    @aiohttp_jinja2.template('manage-policy.html')
    async def manage_policy(request):
        ret = []
        logging.debug('/invoke-service response')
        for device in controller.device_list.devices:
            ret.append({'value': Name.to_str(device.device_name), 'label': Name.to_str(device.device_name)})
        return {'device_list': ret}

    @routes.post('/exec/manage-policy')
    async def exec_manage_policy(request):
        r_json = await request.json()
        device_name = r_json['device_name']
        add_policy = r_json['add_policy']
        data_name = r_json['data_name']
        key_name = r_json['key_name']
        policy_name = r_json['policy_name']

        st_time = time.time()
        if add_policy:
            ret = await controller.manage_policy_add(device_name, data_name, key_name, policy_name)
        else:
            ret = await controller.manage_policy_remove(device_name, policy_name)
        ed_time = time.time()

        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return web.json_response(ret)

    app.add_routes(routes)
    asyncio.ensure_future(controller.run())
    try:
        web.run_app(app, port=6060)
    finally:
        controller.save_db()

if __name__ == '__main__':
    app_main()
