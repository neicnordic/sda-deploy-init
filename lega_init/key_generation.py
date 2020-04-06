from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import os
import secrets
import string
import logging
from pgpy import PGPKey, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from crypt4gh.keys import c4gh
from nacl.public import PrivateKey

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes)

# Logging
FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)


class SecurityConfigGenerator:
    """Security related keys and certificates configuration generator.

    For when one needs to do create keys, certificates and JWT tokens.
    """

    def __init__(self, config_path, name, email):
        """Set things up."""
        self.name = name
        self.email = email
        self._config_path = config_path

    def generate_token(self, password):
        """Generate RSA Key pair to be used to sign token and the JWT Token itself."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')))  # yeah not really that secret

        privkey = serialization.load_pem_private_key(pem, password=password.encode('utf-8'), backend=default_backend())

        return (pem, privkey, public_key)

    def generate_user_auth_key(self, password):
        """Generate user auth for CEGA Users."""
        key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=4096)

        # get public key in OpenSSH format
        public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

        # get private key in PEM container format
        pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')))  # yeah not really that secret

        return (pem, public_key)

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

    def generate_pgp_pair(self, comment, passphrase, armor=True, active=False):
        """Generate PGP key pair to be used by keyserver."""
        # We need to specify all of our preferences because PGPy doesn't have any built-in key preference defaults at this time.
        # This example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
        comment = comment if comment else "Generated for use in LocalEGA."
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

    def generate_cryp4gh_pair(self, passphrase, comment):
        """Generate Crypt4GH key pair to be used in encryption."""
        comment = comment if comment else "Generated for use in LocalEGA."
        # Generate the keys
        sk = PrivateKey.generate()

        pkey = bytes(sk.public_key)
        skey = c4gh.encode_private_key(sk, passphrase.encode(), comment.encode())

        return (pkey, skey)

    def _generate_rsa_key(self, password=None):
        """Generate RSA keys."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        if password is None:
            priv_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption(),)
        else:
            priv_key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),)

        return key, priv_key

    def generate_root_certs(self, country, country_code, location, org, email, org_unit, common_name, password):
        """Generate Root Certificate Authority (CA)."""
        # Following https://cryptography.io/en/latest/x509/tutorial/?highlight=certificate
        key, priv_key = self._generate_rsa_key(password)

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
                                      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, country),
                                      x509.NameAttribute(NameOID.LOCALITY_NAME, location),
                                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
                                      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                                      x509.NameAttribute(NameOID.EMAIL_ADDRESS, email), ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True, content_commitment=True,
                data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        ).add_extension(
            extension=x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        ).add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False
        ).sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(self._config_path / 'certs/root.ca.crt', "w") as root_cert:
            root_cert.write(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        with open(self._config_path / 'certs/root.ca.key', "wb") as root_key:
            root_key.write(priv_key)

    # not sure if this is still needed
    def generate_ssl_certs(self, country, country_code, location, org, email, org_unit, common_name):
        """Generate SSL self signed certificate."""
        # Following https://cryptography.io/en/latest/x509/tutorial/?highlight=certificate
        key, priv_key = self._generate_rsa_key()

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
                                      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, country),
                                      x509.NameAttribute(NameOID.LOCALITY_NAME, location),
                                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
                                      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                                      x509.NameAttribute(NameOID.EMAIL_ADDRESS, email), ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False
        ).sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(self._config_path / 'certs/ega_ssl.cert', "w") as ssl_cert:
            ssl_cert.write(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        with open(self._config_path / 'certs/ega_ssl.key', "w") as ssl_key:
            ssl_key.write(priv_key.decode('utf-8'))

        # return (cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'), priv_key.decode('utf-8'))

    def generate_csr(self, service, country, country_code, location, org, email, org_unit, common_name,
                     kube_ns='default', java_services=None):
        """Generate  Certificate Signing Request (CSR)."""
        # Following https://cryptography.io/en/latest/x509/tutorial/?highlight=certificate
        key, priv_key = self._generate_rsa_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, country),
            x509.NameAttribute(NameOID.LOCALITY_NAME, location),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name + f'.{kube_ns}.svc.cluster.local'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(key, hashes.SHA256(), default_backend())

        with open(self._config_path / f"csr/{service}.csr.pem", "wb") as csr_pem:
            csr_pem.write(csr.public_bytes(serialization.Encoding.PEM))

        with open(self._config_path / f"certs/{service}.ca.key", "wb") as csr_key:
            csr_key.write(priv_key)

        if java_services and service in java_services:
            derkey = key.private_bytes(serialization.Encoding.DER,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())

            with open(self._config_path / f"certs/{service}.ca.key.der", "wb") as csr_key:
                csr_key.write(derkey)

    # Not used but key around for backwards compatibility
    def sign_certificate_request(self, service, password, custom_ca, java_services=None):
        """Sign Certificate Request based on root Certificate Authority (CA)."""
        with open(self._config_path / f"csr/{service}.csr.pem", 'rb') as f:
            csr = x509.load_pem_x509_csr(data=f.read(), backend=default_backend())
        if custom_ca and len(custom_ca) == 2:
            custom_crt, custom_key = custom_ca
            with custom_crt.open(mode='rb') as root_cert:
                root_ca_cert = x509.load_pem_x509_certificate(root_cert.read(), default_backend())

            with custom_key.open(mode='rb') as root_key:
                root_ca_pkey = serialization.load_pem_private_key(root_key.read(), password=password.encode('utf-8'),
                                                                  backend=default_backend())
        else:
            with open(self._config_path / 'certs/root.ca.crt', "rb") as root_cert:
                root_ca_cert = x509.load_pem_x509_certificate(root_cert.read(), default_backend())

            with open(self._config_path / 'certs/root.ca.key', "rb") as root_key:
                root_ca_pkey = serialization.load_pem_private_key(root_key.read(), password=password.encode('utf-8'),
                                                                  backend=default_backend())

        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            root_ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=True,
                data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(root_ca_pkey.public_key()),
            critical=False
        ).sign(
            private_key=root_ca_pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(self._config_path / f"certs/{service}.ca.crt", 'wb') as ca_crt:
            ca_crt.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        if java_services and service in java_services:

            with open(self._config_path / f"certs/{service}.ca.crt.der", "wb") as ca_crt:
                ca_crt.write(cert.public_bytes(encoding=serialization.Encoding.DER))

    def sign_certificate_request_dns(self, service, service_dns, password, custom_ca, java_services=None, kube_ns='default'):
        """Sign Certificate Request based on root Certificate Authority (CA)."""
        with open(self._config_path / f"csr/{service}.csr.pem", 'rb') as f:
            csr = x509.load_pem_x509_csr(data=f.read(), backend=default_backend())

        if custom_ca and len(custom_ca) == 2:
            custom_crt, custom_key = custom_ca
            with custom_crt.open(mode='rb') as root_cert:
                root_ca_cert = x509.load_pem_x509_certificate(root_cert.read(), default_backend())

            with custom_key.open(mode='rb') as root_key:
                root_ca_pkey = serialization.load_pem_private_key(root_key.read(), password=password.encode('utf-8'),
                                                                  backend=default_backend())
        else:
            with open(self._config_path / 'certs/root.ca.crt', "rb") as root_cert:
                root_ca_cert = x509.load_pem_x509_certificate(root_cert.read(), default_backend())

            with open(self._config_path / 'certs/root.ca.key', "rb") as root_key:
                root_ca_pkey = serialization.load_pem_private_key(root_key.read(), password=password.encode('utf-8'),
                                                                  backend=default_backend())

        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            root_ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)
        ).add_extension(
            extension=x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=True,
                data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False, crl_sign=False
            ),
            critical=True
        ).add_extension(
            extension=x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(root_ca_pkey.public_key()),
            critical=False
        ).add_extension(
            extension=x509.SubjectAlternativeName([x509.DNSName(service_dns),
                                                   x509.DNSName(service_dns + f'.{kube_ns}.svc.cluster.local'),
                                                   x509.DNSName(service_dns + f'.{kube_ns}')]),
            critical=False
        ).sign(
            private_key=root_ca_pkey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        with open(self._config_path / f"certs/{service}.ca.crt", 'wb') as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        if java_services and service in java_services:

            with open(self._config_path / f"certs/{service}.ca.crt.der", "wb") as ca_crt:
                ca_crt.write(cert.public_bytes(encoding=serialization.Encoding.DER))
