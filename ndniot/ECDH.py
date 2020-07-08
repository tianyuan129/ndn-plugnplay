from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key
from ecdsa import SigningKey, VerifyingKey, NIST256p
import logging

class ECDH:
    def __init__(self):
        #default curve is secp256r1
        self.ecc_curve = NIST256p
        self.prv_key = SigningKey.generate(curve=self.ecc_curve)
        self.pub_key = self.prv_key.get_verifying_key()
        logging.info('N2 public key:')
        logging.info(self.pub_key.to_string())
        logging.info("N2 public key size: ")
        logging.info(len(self.pub_key.to_string()))
        self.private_key = load_pem_private_key(self.prv_key.to_pem(),password=None,backend=default_backend())
        self.public_key = load_pem_public_key(self.pub_key.to_pem(),backend=default_backend())
        self.derived_key = None

    def encrypt(self, public_key, salt):
        logging.info('N1 public key')
        logging.info(public_key)
        pk = load_pem_public_key(VerifyingKey.from_string(public_key,curve=self.ecc_curve).to_pem(),backend=default_backend())
        shared_key = self.private_key.exchange(ec.ECDH(), pk)
        logging.info('Shared Key:')
        logging.info(shared_key.hex())
        logging.info('Salt:')
        logging.info(salt.hex())
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        logging.info('Symmetric Key:')
        logging.info(self.derived_key.hex())

if __name__ == '__main__':
    key1 = ECDH()
    key2 = ECDH()
    key1.encrypt(key2.public_key,b'hello')
    key2.encrypt(key1.public_key,b'hello')
    print(key1.prv_key.to_string())
    print(key1.pub_key.to_string())
    print(key1.derived_key)
    print(key2.prv_key.to_string())
    print(key2.pub_key.to_string())
    print(key2.derived_key)
