from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import os
import errno
import logging
import secrets
import string
import hashlib
from base64 import b64encode
import yaml
import jwt

from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes)

# Logging
FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)


class ConfigGenerator:
    """Configuration generator.

    For when one needs to do create configuration files.
    """

    def __init__(self, config_path, name, email):
        """Set things up."""
        self.name = name
        self.email = email
        self._config_path = config_path
        self._trace_config = dict()
        self._trace_config.update(secrets={})
        self._trace_secrets = self._trace_config["secrets"]

        if not os.path.exists(self._config_path):
            try:
                os.makedirs(self._config_path)
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

    # Based on
    # https://www.pythonsheets.com/notes/python-crypto.html#aes-cbc-mode-encrypt-via-password-using-cryptography
    # Provided under MIT license: https://github.com/crazyguitar/pysheeet/blob/master/LICENSE

    def _EVP_ByteToKey(self, pwd, md, salt, key_len, iv_len):
        """Derive key and IV.

        Based on https://www.openssl.org/docs/man1.0.2/crypto/EVP_BytesToKey.html
        """
        buf = md(pwd + salt).digest()
        d = buf
        while len(buf) < (iv_len + key_len):
            d = md(d + pwd + salt).digest()
            buf += d
        return buf[:key_len], buf[key_len:key_len + iv_len]

    def aes_encrypt(self, pwd, ptext, md):
        """Encrypt AES."""
        key_len, iv_len = 32, 16

        # generate salt
        salt = os.urandom(8)

        # generate key, iv from password
        key, iv = self._EVP_ByteToKey(pwd, md, salt, key_len, iv_len)

        # pad plaintext
        pad = padding.PKCS7(128).padder()
        ptext = pad.update(ptext) + pad.finalize()

        # create an encryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # encrypt plain text
        ctext = encryptor.update(ptext) + encryptor.finalize()
        ctext = b'Salted__' + salt + ctext

        # encode base64
        return ctext

    def _generate_pgp_pair(self, comment, passphrase, armor):
        """Generate PGP key pair to be used by keyserver."""
        # We need to specify all of our preferences because PGPy doesn't have any built-in key preference defaults at this time.
        # This example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = PGPUID.new(self.name, email=self.email, comment=comment)
        key.add_uid(uid,
                    usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

        # Protecting the key
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        pub_data = str(key.pubkey) if armor else bytes(key.pubkey)  # armored or not
        sec_data = str(key) if armor else bytes(key)  # armored or not

        return (pub_data, sec_data)

    def generate_ssl_certs(self, country, country_code, location, org, email, org_unit="SysDevs", common_name="LocalEGA"):
        """Generate SSL self signed certificate."""
        # Following https://cryptography.io/en/latest/x509/tutorial/?highlight=certificate
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        priv_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                     encryption_algorithm=serialization.NoEncryption(),)

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
                                      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, country),
                                      x509.NameAttribute(NameOID.LOCALITY_NAME, location),
                                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
                                      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                                      x509.NameAttribute(NameOID.EMAIL_ADDRESS, email), ])

        cert = x509.CertificateBuilder().subject_name(
            subject).issuer_name(
            issuer).public_key(
            key.public_key()).serial_number(
            x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1000)).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False,).sign(
            key, hashes.SHA256(), default_backend())

        with open(self._config_path / 'ssl.cert', "w") as ssl_cert:
            ssl_cert.write(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        with open(self._config_path / 'ssl.key', "w") as ssl_key:
            ssl_key.write(priv_key.decode('utf-8'))

        # return (cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'), priv_key.decode('utf-8'))

    def _hash_pass(self, password):
        """Hashing password according to RabbitMQ specs."""
        # 1.Generate a random 32 bit salt:
        # This will generate 32 bits of random data:
        salt = os.urandom(4)

        # 2.Concatenate that with the UTF-8 representation of the password (in this case "simon")
        tmp0 = salt + password.encode('utf-8')

        # 3. Take the SHA256 hash and get the bytes back
        tmp1 = hashlib.sha256(tmp0).digest()

        # 4. Concatenate the salt again:
        salted_hash = salt + tmp1

        # 5. convert to base64 encoding:
        pass_hash = b64encode(salted_hash).decode("utf-8")

        return pass_hash

    def _generate_secret(self, value):
        """Generate secret of specifig value.

        .. note: If the value is of type integer it will generate a random of that value,
        else it will take that value.
        """
        if isinstance(value, int):
            secret = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(value))
            return secret
        else:
            return value

    def generate_cega_mq_auth(self):
        """Generate CEGA MQ auth."""
        generated_secret = self._generate_secret(32)
        cega_defs_mq = """{{"rabbit_version":"3.6",\r\n     "users":[{{"name":"lega",
            "password_hash":"{0}","hashing_algorithm":"rabbit_password_hashing_sha256","tags":"administrator"}}],   "vhosts":[{{"name":"lega"}}],
            "permissions":[{{"user":"lega", "vhost":"lega", "configure":".*", "write":".*", "read":".*"}}],\r\n
            "parameters":[], "global_parameters":[{{"name":"cluster_name", "value":"rabbit@localhost"}}],\r\n     "policies":[],
            "queues":[{{"name":"v1.files.inbox", "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files.stableIDs", "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files",           "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files.completed",       "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files.errors",          "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}}],
            "exchanges":[{{"name":"localega.v1", "vhost":"lega", "type":"topic", "durable":true, "auto_delete":false, "internal":false, "arguments":{{}}}}],
            "bindings":[
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.stableIDs","routing_key":"stableIDs"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files","routing_key":"files"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.inbox","routing_key":"files.inbox"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.error","routing_key":"files.error"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.processing","routing_key":"files.processing"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.completed","routing_key":"files.completed"}}]
                \r\n}}""".format(self._hash_pass(generated_secret))
        cega_config_mq = """%% -*- mode: erlang -*- \r\n%%\r\n[{rabbit,[{loopback_users, [ ] },
        \r\n {disk_free_limit, "1GB"}]},\r\n{rabbitmq_management, [ {load_definitions, "/etc/rabbitmq/defs.json"} ]}\r\n]."""
        self._trace_secrets.update(cega_mq_pass=generated_secret)
        self._trace_config["config"].update(cega_users_user="lega")
        self._trace_config["config"].update(cega_mq_user="lega")

        with open(self._config_path / 'cega.config', "w") as cega_config:
            cega_config.write(cega_config_mq)

        with open(self._config_path / 'cega.json', "w") as cega_defs:
            cega_defs.write(cega_defs_mq)

        return generated_secret

    def generate_token(self, password):
        """Generate RSA Key pair to be used to sign token and the JWT Token itself."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')))  # yeah not really that secret

        privkey = serialization.load_pem_private_key(pem, password=password.encode('utf-8'), backend=default_backend())
        # we set no `exp` and other claims as they are optional in a real scenario these should be set
        # See available claims here: https://www.iana.org/assignments/jwt/jwt.xhtml
        # the important claim is the "authorities"
        token_payload = {"iss": "http://data.epouta.csc.fi",
                         "authorities": ["EGAD01"]}
        encoded = jwt.encode(token_payload, privkey, algorithm='RS256')
        self._trace_secrets.update(token=encoded.decode('utf-8'))

        with open(self._config_path / 'token.key', "wb") as f:
            f.write(pem)

        with open(self._config_path / 'token.pub', "w") as f:
            f.write(public_key.decode('utf-8'))

    def generate_user_auth(self, password):
        """Generate user auth for CEGA Users."""
        key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=4096)

        # get public key in OpenSSH format
        public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

        # get private key in PEM container format
        pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')))  # yeah not really that secret

        # decode to printable strings
        with open(self._config_path / 'dummy.key', "wb") as f:
            f.write(pem)

        with open(self._config_path / 'dummy.pub', "w") as f:
            f.write(public_key.decode('utf-8'))

        user_trace = dict()
        user_trace['username'] = "dummy"
        user_trace['uid'] = 1
        user_trace['gecos'] = "dummy user"
        user_trace.update(pubkey=public_key.decode('utf-8'))
        user_trace.update(password_hash=self._hash_pass(password))
        with open(self._config_path / 'dummy.yml', 'w') as outfile:
            yaml.dump(user_trace, outfile, default_flow_style=False, explicit_start=True)

    def generate_mq_config(self):
        """Generate MQ defintions with custom password."""
        mq_secret = self._generate_secret(32)
        self._trace_config["config"] = {"broker_username": "guest"}
        self._trace_secrets.update(mq_password=mq_secret)
        self._trace_secrets.update(mq_password_hash=self._hash_pass(mq_secret))

    def add_conf_key(self, expire, file_name, comment, passphrase, armor=True, active=False):
        """Create default keys for keyserver.

        .. note: Information for the key is provided as dictionary for ``key_data``,
        and should be in the format ``{'comment': '','passphrase': None, 'armor': True}.
        If a passphrase is not provided it will be generated.``
        """
        comment = comment if comment else "Generated for use in LocalEGA."

        pub, sec = self._generate_pgp_pair(comment, passphrase, armor)
        with open(self._config_path / f'{file_name}.pub', 'w' if armor else 'bw') as f:
            f.write(pub)
        with open(self._config_path / f'{file_name}.sec', 'w' if armor else 'bw') as f:
            f.write(sec)

    def write_trace_yml(self):
        """Create trace YAML file with parameters for deployment."""
        self._trace_secrets.pop("cega_user_public_key", None)
        self._trace_secrets.pop("cega_key_password", None)
        with open(self._config_path / 'trace.yml', 'w') as outfile:
            yaml.dump(self._trace_config, outfile, default_flow_style=False)
