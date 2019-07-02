import logging
import click
import sys
import os
import errno
import json
import shutil
from .configure import ConfigGenerator
from .key_generation import SecurityConfigGenerator
from pathlib import Path
from ruamel.yaml.scalarstring import DoubleQuotedScalarString as dq

# Logging
FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def create_config(_localega, _services, _cega_services, config_path, cega, token_payload):
    """Generate just plain configuration."""
    Path(config_path).mkdir(parents=True, exist_ok=True)
    _here = Path(config_path)
    config_dir = _here
    # Temporary directory to store the CSR
    # will get deleted at the end
    if not os.path.exists(os.path.join(config_dir, 'csr')):
        os.makedirs(os.path.join(config_dir, 'csr'))
    if not os.path.exists(os.path.join(config_dir, 'certs')):
        os.makedirs(os.path.join(config_dir, 'certs'))
    if not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir)
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    # Generate Security related passwords, keys certificates
    sec_config = SecurityConfigGenerator(config_dir, _localega['key']['name'], _localega['email'])

    # generate passwords
    pgp_passphrase = sec_config._generate_secret(32)
    cega_mq_auth_secret = sec_config._generate_secret(32)
    mq_auth_secret = sec_config._generate_secret(32)
    pg_in_password = sec_config._generate_secret(32)
    pg_out_password = sec_config._generate_secret(32)
    s3_access_key = sec_config._generate_secret(16)
    s3_secret_key = sec_config._generate_secret(32)
    shared_pgp_password = sec_config._generate_secret(32)

    token_keys = sec_config.generate_token(_localega['keys_password'])
    # generate root CA
    sec_config.generate_root_certs(country=_localega['cert']['country'], country_code=_localega['cert']['country_code'],
                                   location=_localega['cert']['location'], org=_localega['cert']['org'], email=_localega['email'],
                                   org_unit=_localega['cert']['org_unit'],
                                   common_name=_localega['cert']['common_name'],
                                   password='password',)
    # generate certificates for keyserver EGA_PUBLICKEY_URL
    sec_config.generate_ssl_certs(country=_localega['cert']['country'], country_code=_localega['cert']['country_code'],
                                  location=_localega['cert']['location'], org=_localega['cert']['org'], email=_localega['email'],
                                  org_unit=_localega['cert']['org_unit'],
                                  common_name=_localega['cert']['common_name'],)
    for service in _services:
        sec_config.generate_csr(service, country=_localega['cert']['country'], country_code=_localega['cert']['country_code'],
                                location=_localega['cert']['location'], org=_localega['cert']['org'], email=_localega['email'],
                                org_unit=_localega['cert']['org_unit'],
                                common_name=_localega['cert']['common_name'],)
        sec_config.sign_certificate_request(service, password='password',)
    pgp_pair = sec_config.generate_pgp_pair(comment=_localega['key']['comment'],
                                            passphrase=pgp_passphrase, armor=True, active=True)
    auth_keys = sec_config.generate_user_auth(_localega['keys_password'])

    # Generate actual configuration configuration
    conf = ConfigGenerator(config_path, token_keys, auth_keys, pgp_pair)
    conf.generate_mq_config(mq_auth_secret)
    # generate CentralEGA configuration
    if cega:
        conf.generate_cega_mq_auth(cega_mq_auth_secret)
        conf.generate_user_auth(_localega['keys_password'])
        conf._trace_secrets.update(cega_users_pass=dq(sec_config._generate_secret(32)))
        for service in _cega_services:
            sec_config.generate_csr(service, country=_localega['cert']['country'], country_code=_localega['cert']['country_code'],
                                    location=_localega['cert']['location'], org=_localega['cert']['org'], email=_localega['email'],
                                    org_unit=_localega['cert']['org_unit'],
                                    common_name=_localega['cert']['common_name'],)
            sec_config.sign_certificate_request(service, password='password',)

    conf._trace_secrets.update(pg_in_password=dq(pg_in_password))
    conf._trace_secrets.update(pg_out_password=dq(pg_out_password))
    conf._trace_secrets.update(s3_access_key=dq(s3_access_key))
    conf._trace_secrets.update(s3_secret_key=dq(s3_secret_key))
    conf._trace_secrets.update(shared_pgp_password=dq(shared_pgp_password))
    conf._trace_secrets.update(pgp_passphrase=dq(pgp_passphrase))
    conf.generate_token(token_payload)
    conf.add_conf_key(_localega['key']['id'], armor=True)

    conf.write_trace_yml()
    shutil.rmtree(os.path.join(config_dir, 'csr'))


@click.command()
@click.option('--config-path', help='Specify path for the configuration directory, default is `config` folder.', default='config')
@click.option('--cega', help='Generate mock configuration for CEGA.', is_flag=True)
@click.option('--deploy-config', help='JSON key value pair containing country specific configuration.')
@click.option('--jwt-payload', help='JSON with JWT token payload')
def main(config_path, cega, deploy_config, jwt_payload):
    """Init script generating LocalEGA configuration parameters such as passwords and keys."""
    _services = ['keys', 'dataedge', 'ingest', 'verify', 'mq',
                 'db', 'finalize', 'inbox', 'filedatabase',
                 'res', 's3', 'htsget']
    _cega_services = ['cega-users', 'cega-mq']
    if deploy_config:
        with open(deploy_config) as localega_file:
            _localega = json.load(localega_file)
    else:
        _localega = {
            'email': 'test@csc.fi',
            # Only using one key
            'key': {'name': 'Test PGP',
                    'comment': None,
                    'expire': '30/DEC/30 08:00:00',
                    'id': 'key.1'},
            'cert': {'country': 'Finland', 'country_code': 'FI',
                     'location': 'Espoo', 'org': 'CSC',
                     'common_name': 'NeICLocalEGA',
                     'org_unit': 'EGA SysDev'},
            'keys_password': 'password'
        }
    # Token payload can be adjusted as needed
    if jwt_payload:
        with open(jwt_payload) as localega_file:
            _token_payload = json.load(localega_file)
    else:
        _token_payload = {"iss": "http://data.epouta.csc.fi",
                          "authorities": ["EGAD01"]}

    create_config(_localega, _services, _cega_services, config_path, cega, _token_payload)


if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "deployment config init requires python3.6"
    main()  # pylint: disable=no-value-for-parameter
