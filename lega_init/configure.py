import os
import logging
import hashlib
from base64 import b64encode
import ruamel.yaml
from ruamel.yaml.scalarstring import DoubleQuotedScalarString as dq
import jwt

yaml = ruamel.yaml.YAML()
yaml.default_flow_style = False

# Logging
FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)


class ConfigGenerator:
    """Configuration generator.

    For when one needs to do create configuration files.
    """

    def __init__(self, config_path, token_keys, auth_keys, pgp_pair, c4gh_pair):
        """Set things up."""
        self.token_keys = token_keys
        self.auth_keys = auth_keys
        self.pgp_pair = pgp_pair
        self.c4gh_pair = c4gh_pair
        self._config_path = config_path
        self._trace_config = dict()
        self._trace_config.update(secrets={})
        self._trace_secrets = self._trace_config["secrets"]

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

    def generate_cega_mq_auth(self, generated_secret, mq_user):
        """Generate CEGA MQ auth."""
        cega_defs_mq = """{{"rabbit_version":"3.7",\r\n     "users":[{{"name":"{0}",
            "password_hash":"{1}","hashing_algorithm":"rabbit_password_hashing_sha256","tags":"administrator"}}],   "vhosts":[{{"name":"lega"}}],
            "permissions":[{{"user":"lega", "vhost":"lega", "configure":".*", "write":".*", "read":".*"}}],\r\n
            "parameters":[], "global_parameters":[{{"name":"cluster_name", "value":"rabbit@localhost"}}],\r\n     "policies":[],
            "queues":[{{"name":"v1.files.inbox", "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.stableIDs", "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files",           "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files.completed",       "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files.processing", "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}},
            {{"name":"v1.files.error",          "vhost":"lega", "durable":true, "auto_delete":false, "arguments":{{}}}}],
            "exchanges":[{{"name":"localega.v1", "vhost":"lega", "type":"topic", "durable":true, "auto_delete":false, "internal":false, "arguments":{{}}}}],
            "bindings":[
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.stableIDs","routing_key":"stableIDs"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files","routing_key":"files"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.inbox","routing_key":"files.inbox"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.error","routing_key":"files.error"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.processing","routing_key":"files.processing"}},
              {{"source":"localega.v1","vhost":"lega","destination_type":"queue","arguments":{{}},"destination":"v1.files.completed","routing_key":"files.completed"}}]
                \r\n}}""".format(mq_user, self._hash_pass(generated_secret))
        cega_config_mq = """listeners.ssl.default = 5671
ssl_options.cacertfile                  = /etc/rabbitmq/ssl/root.ca.crt
ssl_options.certfile                    = /etc/rabbitmq/ssl/cega-mq.ca.crt
ssl_options.keyfile                     = /etc/rabbitmq/ssl/cega-mq.ca.key
ssl_options.verify                      = verify_none
ssl_options.fail_if_no_peer_cert        = true
ssl_options.versions.1                  = tlsv1.2
management.load_definitions             = /etc/rabbitmq/conf/cega.json
management.listener.port                = 15671
management.listener.ssl                 = true
management.listener.ssl_opts.cacertfile = /etc/rabbitmq/ssl/root.ca.crt
management.listener.ssl_opts.certfile   = /etc/rabbitmq/ssl/cega-mq.ca.crt
management.listener.ssl_opts.keyfile    = /etc/rabbitmq/ssl/cega-mq.ca.key
default_vhost                           = lega
disk_free_limit.absolute = 1GB"""
        cega_plugins_mq = """[rabbitmq_federation,rabbitmq_federation_management,rabbitmq_management,rabbitmq_shovel,rabbitmq_shovel_management]."""
        self._trace_secrets.update(cega_mq_pass=dq(generated_secret))
        self._trace_config["config"].update(cega_mq_user=dq(mq_user))
        self._trace_config["config"].update(cega_vhost=dq("lega"))
        self._trace_config["config"].update(cega_port=5671)
        self._trace_config["config"].update(cega_mq_ssl=1)

        with open(self._config_path + '/cega.conf', "w") as cega_config:
            cega_config.write(cega_config_mq)

        with open(self._config_path + '/cega.json', "w") as cega_defs:
            cega_defs.write(cega_defs_mq)

        with open(self._config_path + '/cega.plugins', "w") as cega_plugins:
            cega_plugins.write(cega_plugins_mq)

        return generated_secret

    def generate_token(self, token_payload):
        """Generate RSA Key pair to be used to sign token and the JWT Token itself."""
        pem, privkey, public_key = self.token_keys
        # we set no `exp` and other claims as they are optional in a real scenario these should be set
        # See available claims here: https://www.iana.org/assignments/jwt/jwt.xhtml
        # the important claim is the "authorities"
        encoded = jwt.encode(token_payload, privkey, algorithm='RS256')
        self._trace_secrets.update(token=dq(encoded.decode('utf-8')))

        with open(self._config_path + '/token.key', "wb") as f:
            f.write(pem)

        with open(self._config_path + '/token.pub', "w") as f:
            f.write(public_key.decode('utf-8'))

    def generate_user_auth(self, password, username, cega_user):
        """Generate user auth for CEGA Users."""
        pem, public_key = self.auth_keys
        # decode to printable strings
        with open(self._config_path + f'/{username}.key', "wb") as f:
            f.write(pem)

        with open(self._config_path + f'/{username}.pub', "w") as f:
            f.write(public_key.decode('utf-8'))

        self._trace_config["config"].update(cega_users_user=dq(cega_user))
        pubkey = public_key.decode('utf-8')
        cega_users = """[{{"username": "{2}",\r\n  "uid": 1,
  "passwordHash": "{0}",\r\n  "gecos": "{2} user",\r\n  "sshPublicKey": "{1}",
  "enabled": null\r\n}}]""".format(self._hash_pass(password), pubkey, username)

        with open(self._config_path + '/users.json', "w") as cega_defs:
            cega_defs.write(cega_users)

    def generate_mq_config(self, mq_secret, mq_user):
        """Generate MQ defintions with custom password."""
        self._trace_config["config"] = {"broker_username": dq(mq_user)}
        self._trace_secrets.update(mq_password=dq(mq_secret))
        self._trace_secrets.update(mq_password_hash=dq(self._hash_pass(mq_secret)))

    def add_conf_key(self, file_name, armor=True):
        """Create default keys for keyserver.

        .. note: Information for the key is provided as dictionary for ``key_data``,
        and should be in the format ``{'comment': '','passphrase': None, 'armor': True}.
        If a passphrase is not provided it will be generated.``
        """
        pub, sec = self.pgp_pair

        pkey, skey = self.c4gh_pair

        # os.umask(0o222)  # Restrict to r-- r-- r--
        with open(self._config_path + f'/{file_name}.c4gh.pub', 'bw', ) as f:
            f.write(b'-----BEGIN CRYPT4GH PUBLIC KEY-----\n')
            f.write(b64encode(pkey))
            f.write(b'\n-----END CRYPT4GH PUBLIC KEY-----\n')
        with open(self._config_path + f'/{file_name}.pub', 'w' if armor else 'bw') as f:
            f.write(pub)

        # os.umask(0o277)  # Restrict to r-- --- ---
        with open(self._config_path + f'/{file_name}.c4gh.sec', 'bw') as f:
            f.write(b'-----BEGIN CRYPT4GH PRIVATE KEY-----\n')
            f.write(b64encode(skey))
            f.write(b'\n-----END CRYPT4GH PRIVATE KEY-----\n')
        with open(self._config_path + f'/{file_name}.sec', 'w' if armor else 'bw') as f:
            f.write(sec)

    def write_trace_yml(self):
        """Create trace YAML file with parameters for deployment."""
        self._trace_secrets.pop("cega_user_public_key", None)
        self._trace_secrets.pop("cega_key_password", None)
        self._trace_config["config"].update(tls_cert_ending=".ca.crt")
        self._trace_config["config"].update(tls_key_ending=".ca.key")
        self._trace_config["config"].update(tls_ca_root_file="root.ca.crt")
        with open(self._config_path + '/trace.yml', 'w') as outfile:
            yaml.dump(self._trace_config, outfile)
