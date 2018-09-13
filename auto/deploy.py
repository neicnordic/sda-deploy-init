import logging
from kube import kubernetes_deployment, create_config
import click

# Logging
FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


@click.command()
@click.option('--config', is_flag=True,
              help='Flag for generating configuration if does not exist, or generating a new one.')
@click.option('--deploy', is_flag=True,
              help='Deploying the configuration secrets and pods.')
@click.option('--ns', default="testing", help='Deployment namespace, defaults to "testing".')
@click.option('--cega-mq', default='cega-mq', help='CEGA MQ IP, for fake default "cega-mq".')
@click.option('--cega-pwd', help='CEGA MQ Password, for fake CEGA MQ it is set up with a default.')
@click.option('--cega-api', default='http://cega-users.testing:8001/user/',
              help='CEGA User endpoint, default http://cega-users.testing:8001/user/.')
@click.option('--key-pass', default='password', help='CEGA Users RSA key password.')
@click.option('--fake-cega', is_flag=True,
              help='Deploy fake CEGA.')
def main(config, deploy, ns, cega_mq, cega_api, cega_pwd, key_pass, fake_cega):
    """Local EGA deployment script."""
    _localega = {
        'role': 'LocalEGA',
        'email': 'test@csc.fi',
        'services': {'keys': 'keys',
                     'inbox': 'inbox',
                     'ingest': 'ingest',
                     's3': 'minio',
                     'broker': 'mq',
                     'db': 'db',
                     'verify': 'verify'},
        # Only using one key
        'key': {'name': 'Test PGP',
                'comment': None,
                'expire': '30/DEC/19 08:00:00',
                'id': 'key.1'},
        'ssl': {'country': 'Finland', 'country_code': 'FI', 'location': 'Espoo', 'org': 'CSC'},
        'cega': {'user': 'lega',
                 'endpoint': cega_api}
    }

    trace_config = create_config(_localega, ns, cega_mq, cega_api, cega_pwd, key_pass)
    if deploy:
        kubernetes_deployment(_localega, trace_config, ns, fake_cega)


if __name__ == '__main__':
    main()
