import asyncio
import logging
import plyvel
import struct
import time
from hashlib import sha256
from os import urandom
from random import SystemRandom
from typing import Optional

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

from ndn.security.signer import HmacSha256Signer
from ndn.app_support.security_v2 import parse_certificate
from ndn.encoding import InterestParam, BinaryStr, FormalName, SignaturePtrs, SignatureType, Name, Component
from ndn.utils import timestamp, gen_nonce
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout

from .db_storage import *
from .config_source_helper import *
from .pnp_protocols import *

default_prefix = "ndn-plugnplay"
default_udp_multi_uri = "udp4://224.0.23.170:56363"
default_ether_multi_uri = "ether://[01:00:5e:00:17:aa]"
config_source_port = 6363


class ConfigSource:
    """
    NDN PnP config_source.

    :ivar app: the python-ndn app
    :ivar system_prefix: a string representing the home namespace
    :ivar system_anchor: a TLV format NDN certificate
    :ivar db: the database handler
    :ivar device_list: the list of device
    :ivar access_list: the list of access rights
    :ivar shared_secret_list: the list of already-shared secrets
    """

    def __init__(self, emit_func):
        self.newly_pub_command = None
        self.newly_pub_payload = None
        self.wait_fetch_cmd_event = None
        self.emit = emit_func
        self.running = True
        self.listen_to_boot_request = False
        self.listen_to_cert_request = False
        self.boot_state = None
        self.boot_event = None

        self.app = NDNApp()
        self.system_prefix = None
        self.system_anchor = None
        self.db = None
        self.device_list = DeviceList()

    def save_db(self):
        """
        Save the state into the database.
        """
        logging.debug('Save state to DB')
        if self.db:
            wb = self.db.write_batch()

            wb.put(b'device_list', self.device_list.encode())
            wb.write()
            self.db.close()

    def system_init(self):
        """
        Init the system in terms of:
        Step 1: Create/load system prefix and system anchor from the storage if any
        Step 2: Create/load device list, service list, access rights, and shared secrets from the storage
        """

        logging.info("Server starts its initialization")
        # create or get existing state
        # Step One: Meta Info
        # 1. get system prefix from storage (from Level DB)
        import os
        db_dir = os.path.expanduser('~/.ndn-plugnplay/')
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.db = plyvel.DB(db_dir, create_if_missing=True)
        ret = self.db.get(b'system_prefix')
        if ret:
            logging.info('Found system prefix from db')
            self.system_prefix = ret.decode()
        else:
            self.system_prefix = default_prefix
            self.db.put(b'system_prefix', default_prefix.encode())
        # 2. get system root anchor certificate and private key (from keychain)
        anchor_identity = self.app.keychain.touch_identity(self.system_prefix)
        anchor_key = anchor_identity.default_key()
        self.system_anchor = anchor_key.default_cert().data
        logging.info("Server finishes the step 1 initialization")

        # Step Two: App Layer Support (from Level DB)
        # 1. DEVICES: get all the certificates for devices from storage
        ret = self.db.get(b'device_list')
        if ret:
            logging.info('Found device list from db')
            self.device_list = DeviceList.parse(ret)

        # add example device
        example_added = False
        for device in self.device_list.devices:
            if Name.to_str(device.device_name) == "/ndn/example":
                example_added = True
                break
        if not example_added:
            item = DeviceItem()
            item.device_name = Name.from_str("/ndn/example")
            item.device_ip = str.encode("192.168.99.123")
            item.device_port = str.encode("5678")
            item.device_active = str.encode("inactive")
            self.device_list.devices.append(item)

    async def connectivity_init(self):
        """
        Init the system in terms of:
        Step 3: Configure network interface, forwarding strategy, and route
        """

        # Step Three: Configure Face and Route
        # 1. Find/create NFD's multicast Face
        udp_face_id = await query_face_id(self.app, default_udp_multi_uri)
        ether_face_id = await query_face_id(self.app, default_ether_multi_uri)
        if udp_face_id is None and ether_face_id is None:
            logging.fatal("Cannot find existing multicast face")
            return
        # # 2. Set up NFD's route from system prefix to multicast faces
        if udp_face_id is not None:
            ret = await add_route(self.app, self.system_prefix, udp_face_id)
            if ret is True:
                logging.info("Successfully add udp multicast route.")
        if ether_face_id is not None:
            ether_route_success = await add_route(self.app, self.system_prefix, ether_face_id)
            if ret is True:
                logging.info("Successfully add ethernet multicast route.")

        # 3. Set up NFD's multicast strategy for system namespace
        ret = await set_strategy(self.app, self.system_prefix, "/localhost/nfd/strategy/multicast")
        if ret is True:
            logging.info("Successfully add multicast strategy.")
            logging.info("Server finishes the step 3 initialization")
        else:
            logging.fatal("Cannot set up the strategy for system prefix")

        @self.app.route('/ndn/config')
        def on_config_interest(name: FormalName, param: InterestParam, pp_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is a config Interest: /ndn/config/<nonce>

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters
            """

            self.process_config_request(name)

        await asyncio.sleep(0.01)

        @self.app.route(self.system_prefix + '/cert')
        def on_cert_request_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is a certificate request during config

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters
            """
            self.process_cert_request(name, app_param)

        await asyncio.sleep(0.01)

        @self.app.route(self.system_prefix + '/schema')
        def on_schema_request_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is a trust schema request during config

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters
            """
            self.process_schema_request(name, app_param)

        await asyncio.sleep(0.1)

        @self.app.route(self.system_prefix + '/nd/arrival')
        def on_nd_arrival_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is a NDND Arrival Interest during bootstrapping

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters
            """
            asyncio.ensure_future(self.process_nd_arrival(name, app_param))
        await asyncio.sleep(0.1)

        @self.app.route(self.system_prefix + '/nd/nd-info')
        def on_nd_client_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is an NDND client request

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters

            """
            # encode all device in the list back to clients
            has_empty_list = True
            result = NeighborInfo()
            active_list = NeighborList()
            for device in self.device_list.devices:
                has_empty_list = False
                logging.debug('giving back all devices available')
                item = NeighborParam()
                item.name = device.device_name
                item.ip_addr = device.device_ip
                item.port = device.device_port
                active_list.neighbor_list.append(item)
            
            if not has_empty_list:
                result.neighbor_info = active_list.encode()
                self.app.put_data(name, result.encode(), freshness_period=3000, identity=self.system_prefix)
                logging.debug("Replied device set back to the device")
            else:
                logging.debug("Don't have devices needed info, won't reply")


        await asyncio.sleep(0.01)

        # then begin probe
        asyncio.ensure_future(self.probe_all_face())

    async def probe_all_face(self):
        """
        This will periodically probe all faces inside device list
        N times timeout will remove face and route
        """
        while True:
            await asyncio.sleep(6)
            logging.debug("let's probe")
            for device in self.device_list.devices:
                # skip example and inactive device
                if Name.to_str(device.device_name) == "/ndn/example" or \
                   bytes(device.device_active).decode() == "inactive":
                    continue
                
                # I know it's not the correct way, but what is the correct way?
                interest_name = Name.from_str(Name.to_str(device.device_name))
                interest_name.append("nd-info")
                interest_name.append(str(gen_nonce()))
                
                n_retries = 3
                is_success = False
                while n_retries > 0:
                    logging.debug(f'sending interest: {Name.to_str(interest_name)}')
                    ret = await self.express_interest(interest_name, None, True, False, True)
                    if ret['response_type'] == 'Data' and ret['content'] is not None:
                        # update record
                        neighbor_param_bytes = parse_and_check_tl(bytes(ret['content']), TLV_NEIGHBOR_PARAM)
                        neighbor_param = NeighborParam.parse(neighbor_param_bytes)
                        # name as validation given it won't change
                        if Name.to_str(neighbor_param.name) != Name.to_str(device.device_name):
                            logging.debug("name not correct, force remove")
                            break
                        # update other elements
                        device.device_ip = neighbor_param.ip_addr
                        device.device_port = neighbor_param.port
                        is_success = True
                        break
                    if ret['response_type'] == 'NetworkNack':
                        logging.debug(f'Nacked with reason')
                        await asyncio.sleep(1)
                        n_retries = n_retries - 1
                    if ret['response_type'] == 'Timeout':
                        logging.debug(f'Timeout')
                        await asyncio.sleep(1)
                        n_retries = n_retries - 1
                if not is_success:
                    # remove face and route, labal as inactive
                    logging.debug("should remove")
                    device.device_active = str.encode("inactive")
                    uri = 'udp4://' + bytes(device.device_ip).decode() + ':' + bytes(device.device_port).decode()
                    face_id = await query_face_id(self.app, uri)
                    # TODO: replace this with method calls
                    p = subprocess.run(['nfdc', 'face', 'destroy', str(face_id)], stdout=subprocess.PIPE)
                    removed = await remove_route(self.app, Name.to_str(device.device_name), face_id)
                    if not removed:
                        logging.debug("removal not success")



    def process_config_request(self, name):
        """
        Process device's config request.

        :param name: Interest packet name
        """
        logging.info(self.system_anchor)

        logging.info("[SIGN ON]: interest received")
        response = SignOnResponse()
        cert_bytes = parse_and_check_tl(self.system_anchor, TypeNumber.DATA)
        response.anchor = cert_bytes
        logging.info(response.encode())

        self.app.put_data(name, response.encode(), freshness_period=3000, identity=self.system_prefix)

        self.listen_to_cert_request = True

    def process_cert_request(self, name, app_param):
        logging.info("[CERT REQ]: interest received")
        # /ndn-plugnplay/cert/<nonce>
        logging.info(name)

        # create identity and key for the device
        session = Name.to_str([name[-1]])[1:]
        device_name = Name.to_str(self.system_prefix) + '/device-' + session

        # generate a random device name: /ndn-plugnplay/device-<nonce>
        device_key = self.app.keychain.touch_identity(device_name).default_key()
        
        logging.info(device_name)
        p = subprocess.run(['ndnsec-sign-req', device_name], stdout=subprocess.PIPE)
        wire = base64.b64decode(p.stdout)
        logging.debug('result from ndnsec-sign-req')
        logging.debug(wire)

        reqname = 'session-' + session + '.req'
        certname = 'session-' + session + '.cert'
        subprocess.run(['touch', reqname, certname], stdout=subprocess.PIPE)

        # write cert requst
        with open(reqname, 'wb') as f:  
            f.write(p.stdout)
        p = subprocess.run(['ndnsec-cert-gen', '-s', Name.to_str(self.system_prefix), '-i', 'config-source', reqname], stdout=subprocess.PIPE)
        # write anchor signed cert
        with open(certname, 'wb') as f:  
            f.write(p.stdout)
        # install this cert
        p = subprocess.run(['ndnsec-cert-install', certname], stdout=subprocess.PIPE)
        # delete session file
        subprocess.run(['rm', reqname, certname], stdout=subprocess.PIPE)

        # export to safebag
        p = subprocess.run(['ndnsec-export', device_name, '-P', '1234'], stdout=subprocess.PIPE)
        wire = base64.b64decode(p.stdout)
        logging.debug('result from ndnsec-export')
        logging.debug(wire)

        # add to list
        already_added = False
        name_to_register = device_name
        for device in self.device_list.devices:
            if Name.to_str(name_to_register) == Name.to_str(device.device_name):
                logging.debug('device already added')
                already_added = True
        if not already_added:
            device = DeviceItem()
            device.device_name = name_to_register
            device.device_active = str.encode("inactive")
            self.device_list.devices.append(device)

        # only for local test: delete identity
        device_key = self.app.keychain.del_identity(Name.to_str(device_name))
        # register it back to root prefix
        self.app.keychain.set_default_identity(self.system_prefix)
        self.app.put_data(name, wire, freshness_period=3000, identity = self.system_prefix)

    def process_schema_request(self, name, app_param):
        logging.info("[SCHEMA]: interest received")
        logging.info(name)

        # /ndn-plugnplay/schema/<nonce>
        #TODO: check such device exist or not
        file_path = 'ndnpnp/pnp.conf'
        if not os.path.exists(file_path):
            logging.error(f'file {file_path} does not exist')
        with open(file_path, 'rb') as binary_file:
            b_array = bytearray(binary_file.read())
        if len(b_array) == 0:
            logging.warning("File is empty")
        self.app.put_data(name, b_array, freshness_period=3000, identity = self.system_prefix)

    async def process_nd_arrival(self, name: FormalName, app_param: Optional[BinaryStr]):
        """
        OnInterest callback when there is an nd arrival Interest

        :param name: Interest packet name
        :param param: Interest parameters
        :app_param: Interest application paramters

        Packet format: prefix = /ndn/nd/arrival/<name_length>/<Name>/<IP>/<Port>/<timestamp>
        App Parameter format:
        """
        # the length should be one
        device_name_length = int(Name.to_str([name[3]])[1:])
        device_name = name[4: 4 + device_name_length]
        device_ip = Name.to_str([name[4 + device_name_length]])[1:]
        device_port = Name.to_str([name[5 + device_name_length]])[1:] 
        logging.debug("device name length: %d", device_name_length)
        logging.debug("device name: %s", Name.to_str(device_name))
        logging.debug("device ip: %s, device port: %s", device_ip, device_port)
        
        name_to_register = device_name
        for device in self.device_list.devices:
            if Name.to_str(name_to_register) == Name.to_str(device.device_name):
                logging.debug('device already added, update ip addr and port')
                device.device_ip = str.encode(device_ip)
                device.device_port = str.encode(device_port)
                device.device_active = str.encode("active")

                # setting up face and route
                uri = 'udp4://' + device_ip + ':' + device_port
                # TODO: replace this with method calls
                p = subprocess.run(['nfdc', 'face', 'create', 'remote', uri], stdout=subprocess.PIPE)
                face_id = await query_face_id(self.app, uri)
                route_added = await add_route(self.app, Name.to_str(device_name), face_id)
                if not route_added:
                    logging.debug("route adding failed for %s on face id %d", Name.to_str(device_name), face_id)
                break
        
        # arrival ack
        self.app.put_data(name, Name.to_bytes(name_to_register), freshness_period=3000, identity = self.system_prefix)

    async def verify_device_ecdsa_signature(self, name: FormalName, sig: SignaturePtrs) -> bool:
        sig_info = sig.signature_info
        covered_part = sig.signature_covered_part
        sig_value = sig.signature_value_buf
        if not sig_info or sig_info.signature_type != SignatureType.SHA256_WITH_ECDSA:
            return False
        if not covered_part or not sig_value:
            return False
        identity = Name.to_str(sig_info.key_locator.name[:2])
        logging.debug(identity)
        key_bits = None
        try:
            key_bits = self.app.keychain.get(identity).default_key().key_bits
        except (KeyError, AttributeError):
            logging.error('Cannot find pub key from keychain')
            return False
        pk = ECC.import_key(key_bits)
        verifier = DSS.new(pk, 'fips-186-3', 'der')
        sha256_hash = SHA256.new()
        for blk in covered_part:
            sha256_hash.update(blk)
        logging.debug(bytes(sig_value))
        logging.debug(len(bytes(sig_value)))
        try:
            verifier.verify(sha256_hash, bytes(sig_value))
        except ValueError:
            return False
        return True

    
    async def express_interest(self, name, app_param, be_fresh: bool, be_prefix: bool, need_sig: bool):
        ret = {'name': Name.to_str(name)}
        try:
            if need_sig:
                data_name, meta_info, content = await self.app.express_interest(name, app_param,
                                                                                must_be_fresh=be_fresh,
                                                                                can_be_prefix=be_prefix,
                                                                                identity=self.system_prefix,
                                                                                validator=self.verify_device_ecdsa_signature)
            else:
                data_name, meta_info, content = await self.app.express_interest(name, app_param,
                                                                                must_be_fresh=be_fresh,
                                                                                can_be_prefix=be_prefix)

        except InterestNack as e:
            ret['response_type'] = 'NetworkNack'
            ret['reason'] = e.reason
        except InterestTimeout:
            ret['response_type'] = 'Timeout'
        else:
            ret['response_type'] = 'Data'
            ret['name'] = Name.to_str(data_name)
            ret['freshness_period'] = meta_info.freshness_period
            ret['content_type'] = meta_info.content_type
            ret['content'] = content
        return ret

    async def run(self):
        logging.info("Restarting app...")
        while True:
            try:
                await self.app.main_loop(self.connectivity_init())
            except KeyboardInterrupt:
                logging.info('Receiving Ctrl+C, shutdown')
                break
            except (FileNotFoundError, ConnectionRefusedError):
                logging.info("NFD disconnected...")
            finally:
                self.app.shutdown()
            await asyncio.sleep(3.0)

    ###################
    @staticmethod
    def get_time_now_ms():
        return round(time.time() * 1000.0)

    def on_register_failed(self, prefix):
        logging.fatal("Prefix registration failed: %s", prefix)

