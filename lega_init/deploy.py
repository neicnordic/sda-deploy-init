import logging
import click
import sys
from .configure import ConfigGenerator
from pathlib import Path

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

    # Generate Configuration
    conf = ConfigGenerator(config_dir,  _localega['key']['name'],  _localega['email'])
    if cega:
        conf.generate_cega_mq_auth()
        conf.generate_user_auth('password')
        conf._trace_secrets.update(cega_creds=conf._generate_secret(32))
    postgres_password = conf._generate_secret(32)
    conf.generate_mq_config()
    conf._trace_secrets.update(postgres_password=postgres_password)
    s3_access = conf._generate_secret(16)
    conf._trace_secrets.update(s3_access=s3_access)
    s3_secret = conf._generate_secret(32)
    conf._trace_secrets.update(s3_secret=s3_secret)
    shared_pgp_password = conf._generate_secret(32)
    conf._trace_secrets.update(shared_pgp_password=shared_pgp_password)
    pgp_passphrase = conf._generate_secret(32)
    conf._trace_secrets.update(pgp_passphrase=pgp_passphrase)

    conf.add_conf_key(_localega['key']['expire'], _localega['key']['id'], comment=_localega['key']['comment'],
                      passphrase=pgp_passphrase, armor=True, active=True)
    conf.generate_ssl_certs(country=_localega['ssl']['country'], country_code=_localega['ssl']['country_code'],
                            location=_localega['ssl']['location'], org=_localega['ssl']['org'], email=_localega['email'])

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
    }

    create_config(_localega, config_path, cega)


if __name__ == '__main__':
    assert sys.version_info >= (3, 6), "deployment config init requires python3.6"
    main()
