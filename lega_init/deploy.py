import logging
import click
import sys
import os
import errno
from .configure import ConfigGenerator
from .key_generation import SecurityConfigGenerator
from pathlib import Path
from ruamel.yaml.scalarstring import DoubleQuotedScalarString as dq

# Logging
FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def create_config(_localega, config_path, cega):
    """Generate just plain configuration."""
    Path(config_path).mkdir(parents=True, exist_ok=True)
    _here = Path(config_path)
    config_dir = _here

    if not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir)
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    # Generate Configuration
    token_payload = {"iss": "http://data.epouta.csc.fi",
                     "authorities": ["EGAD01"]}
    sec_config = SecurityConfigGenerator(config_dir, _localega['key']['name'], _localega['email'])
    token_keys = sec_config.generate_token(_localega['keys_password'])
    pgp_passphrase = sec_config._generate_secret(32)
    cega_mq_auth_secret = sec_config._generate_secret(32)
    mq_auth_secret = sec_config._generate_secret(32)
    sec_config.generate_ssl_certs(country=_localega['ssl']['country'], country_code=_localega['ssl']['country_code'],
                                  location=_localega['ssl']['location'], org=_localega['ssl']['org'], email=_localega['email'])
    pgp_pair = sec_config.generate_pgp_pair(comment=_localega['key']['comment'],
                                            passphrase=pgp_passphrase, armor=True, active=True)
    auth_keys = sec_config.generate_user_auth(_localega['keys_password'])
    conf = ConfigGenerator(config_path, token_keys, auth_keys, pgp_pair)
    conf.generate_mq_config(mq_auth_secret)
    if cega:
        conf.generate_cega_mq_auth(cega_mq_auth_secret)
        conf.generate_user_auth(_localega['keys_password'])
        conf._trace_secrets.update(cega_users_pass=dq(sec_config._generate_secret(32)))
    pg_in_password = sec_config._generate_secret(32)
    pg_out_password = sec_config._generate_secret(32)
    conf._trace_secrets.update(pg_in_password=dq(pg_in_password))
    conf._trace_secrets.update(pg_out_password=dq(pg_out_password))
    s3_access_key = sec_config._generate_secret(16)
    conf._trace_secrets.update(s3_access_key=dq(s3_access_key))
    s3_secret_key = sec_config._generate_secret(32)
    conf._trace_secrets.update(s3_secret_key=dq(s3_secret_key))
    shared_pgp_password = sec_config._generate_secret(32)
    conf._trace_secrets.update(shared_pgp_password=dq(shared_pgp_password))
    conf._trace_secrets.update(pgp_passphrase=dq(pgp_passphrase))
    conf.generate_token(token_payload)
    conf.add_conf_key(_localega['key']['id'], armor=True)

    conf.write_trace_yml()


@click.command()
@click.option('--config-path', help='Specify path for the configuration directory, default is `config` folder.', default='config')
@click.option('--cega', help='Generate mock configuration for CEGA.', is_flag=True)
def main(config_path, cega):
    """Init script generating LocalEGA configuration parameters such as passwords and keys."""
    _localega = {
        'email': 'test@csc.fi',
        # Only using one key
        'key': {'name': 'Test PGP',
                'comment': None,
                'expire': '30/DEC/30 08:00:00',
                'id': 'key.1'},
        'ssl': {'country': 'Finland', 'country_code': 'FI', 'location': 'Espoo', 'org': 'CSC'},
        'keys_password': 'password'
    }

    create_config(_localega, config_path, cega)


if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "deployment config init requires python3.6"
    main()
