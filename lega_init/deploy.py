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


def sign_cert(sec_config, conf, services, svc_prefix):
    """Generate certificates for services."""
    for service in services:
        if svc_prefix != '':
            _cn = svc_prefix + '-' + service['name']
        else:
            _cn = service['name']
        if 'dns' in service and service['dns']:
            sec_config.generate_csr(service['name'], country=conf['svc_cert']['country'], country_code=conf['svc_cert']['country_code'],
                                    location=conf['svc_cert']['location'], org=conf['svc_cert']['org'], email=conf['email'],
                                    org_unit=conf['svc_cert']['org_unit'],
                                    common_name=service['dns'],
                                    kube_ns=service['ns'],)
            sec_config.sign_certificate_request_dns(service['name'], service['dns'], password='password',
                                                    kube_ns=service['ns'],)
        else:
            sec_config.generate_csr(service['name'], country=conf['svc_cert']['country'], country_code=conf['svc_cert']['country_code'],
                                    location=conf['svc_cert']['location'], org=conf['svc_cert']['org'], email=conf['email'],
                                    org_unit=conf['svc_cert']['org_unit'],
                                    common_name=_cn,
                                    kube_ns=service['ns'],)
            sec_config.sign_certificate_request_dns(service['name'], _cn, password='password',
                                                    kube_ns=service['ns'],)


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
    sec_config.generate_root_certs(country=_localega['root_cert']['country'], country_code=_localega['root_cert']['country_code'],
                                   location=_localega['root_cert']['location'], org=_localega['root_cert']['org'], email=_localega['email'],
                                   org_unit=_localega['root_cert']['org_unit'],
                                   common_name=_localega['root_cert']['cn'],
                                   password='password',)
    # generate certificates for keyserver EGA_PUBLICKEY_URL
    # this will be for localhost host
    sec_config.generate_ssl_certs(country=_localega['root_cert']['country'], country_code=_localega['root_cert']['country_code'],
                                  location=_localega['root_cert']['location'], org=_localega['root_cert']['org'], email=_localega['email'],
                                  org_unit=_localega['root_cert']['org_unit'],
                                  common_name=_localega['root_cert']['cn'],)
    sign_cert(sec_config, _localega, _services, _localega['prefix_lega'])
    pgp_pair = sec_config.generate_pgp_pair(comment=_localega['key']['comment'],
                                            passphrase=pgp_passphrase, armor=True, active=True)
    auth_keys = sec_config.generate_user_auth_key(_localega['keys_password'])

    # Generate actual configuration configuration
    conf = ConfigGenerator(config_path, token_keys, auth_keys, pgp_pair)
    conf.generate_mq_config(mq_auth_secret, _localega['broker_username'])
    # generate CentralEGA configuration
    if cega:
        conf.generate_cega_mq_auth(cega_mq_auth_secret, _localega['broker_username'])
        conf.generate_user_auth(_localega['inbox_user'], _localega['inbox_user'], _localega['cega_user'])
        conf._trace_secrets.update(cega_users_pass=dq(sec_config._generate_secret(32)))
        sign_cert(sec_config, _localega, _cega_services, _localega['prefix_cega'])

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
@click.option('--svc-config', help='JSON with LocalEGA service list, DNSName (Optional) and K8s namespace')
@click.option('--cega-svc-config', help='JSON with CEGA service list, DNSName (Optional) and K8s namespace')
def main(config_path, cega, deploy_config, jwt_payload, svc_config, cega_svc_config):
    """Init script generating LocalEGA configuration parameters such as passwords and keys."""
    if svc_config:
        with open(svc_config) as svc_file:
            _services = json.load(svc_file)
    else:
        _services = [{'name': 's3', 'dns': 'minio', 'ns': 'default'},
                     {'name': 'keys', 'ns': 'default'}, {'name': 'dataedge', 'ns': 'default'},
                     {'name': 'htsget', 'ns': 'default'}, {'name': 'res', 'ns': 'default'},
                     {'name': 'filedatabase', 'ns': 'default'},
                     {'name': 'inbox', 'ns': 'default'}, {'name': 'ingest', 'ns': 'default'},
                     {'name': 'finalize', 'ns': 'default'}, {'name': 'verify', 'ns': 'default'},
                     {'name': 'mq-server', 'ns': 'default'}, {'name': 'db', 'ns': 'default'},
                     # In case we run this in testing environment
                     {'name': 'tester', 'ns': 'default'}]
    if cega_svc_config:
        with open(cega_svc_config) as cega_svc_file:
            _cega_services = json.load(cega_svc_file)
    else:
        _cega_services = [{'name': 'cega-users', 'ns': 'default'}, {'name': 'cega-mq', 'ns': 'default'}]
    if deploy_config:
        with open(deploy_config) as localega_file:
            _localega = json.load(localega_file)
    else:
        _localega = {
            'email': 'test@csc.fi',
            'broker_username': 'lega',
            'inbox_user': 'dummy',
            'cega_user': 'legatest',
            # Only using one key
            'key': {'name': 'Test PGP',
                    'comment': None,
                    'expire': '30/DEC/30 08:00:00',
                    'id': 'key.1'},
            'root_cert': {'country': 'Finland', 'country_code': 'FI',
                          'location': 'Espoo', 'org': 'CSC',
                          'cn': 'lega',
                          'org_unit': 'NeIC System Developers'},
            'svc_cert': {'country': 'Finland', 'country_code': 'FI',
                         'location': 'Espoo', 'org': 'CSC',
                         'org_unit': 'NeIC System Developers'},
            'keys_password': 'password',
            # the prefixes represent the default names for the services in deployments
            # If one is using helm charts or prod/test environments adjust accordingly
            'prefix_lega': 'localega',
            'prefix_cega': ''
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
