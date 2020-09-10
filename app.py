import argparse
import asyncio
import time
import os
import logging
from ndnpnp.config_source import ConfigSource
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
    parser = argparse.ArgumentParser(description='system prefix')
    parser.add_argument('--prefix',
                        required=False, default='ndn-plugnplay',
                        help='prefix of the system')
    parser.add_argument('--convention',
                        required=False, default='device',
                        help='device naming convention: /<system-prefix>/<input>-<nonce>')
    args = parser.parse_args()

    logging.basicConfig(format='[{asctime}]{levelname}:{message}', datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG, style='{')

    base_path = os.getcwd()
    # Serve static content from /static
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(os.path.join(base_path, 'templates')))
    app.router.add_static(prefix='/static', path=os.path.join(base_path, 'static'))
    routes = web.RouteTableDef()
    # Create SocketIO async server for config_source
    sio = socketio.AsyncServer(async_mode='aiohttp')
    sio.attach(app)
    config_source = ConfigSource(sio.emit, prefix = args.prefix, convention = args.convention)
    config_source.system_init()

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
        metainfo.append({"information":"System Prefix", "value": config_source.system_prefix})
        metainfo.append({"information": "Available Devices", "value": str(len(config_source.device_list.devices))})
        return {'metainfo': metainfo}

    # device list
    @routes.get('/device-list')
    @aiohttp_jinja2.template('device-list.html')
    async def device_list(request):
        ret = []
        for device in config_source.device_list.devices:
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
            # config_source.app.keychain.del_identity(data['deviceIdentityName'])
            os.system('ndnsec-delete ' + data['device_name'])
        except KeyError:
            pass  # great, the key has already been removed
        # delete from database
        config_source.device_list.devices = [device for device in config_source.device_list.devices
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
        ret = await config_source.express_interest(name, param.encode(), must_be_fresh, can_be_prefix, signed_interest)
        ed_time = time.time()

        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return web.json_response(ret)

    app.add_routes(routes)
    asyncio.ensure_future(config_source.run())
    try:
        web.run_app(app, port=6060)
    finally:
        config_source.save_db()

if __name__ == '__main__':
    app_main()
